import struct, sys, lzma, zlib

MAGIC=b'B256\x02'
HDRLEN=80
LCG_A=0x5851f42d4c957f2d; LCG_C=0x14057b7ef767814f; MASK64=(1<<64)-1
STRIDES=[2,3,4,7]

# ---------- transforms (stored <-> plain) ----------
def deinter(p,s):
    n=len(p); out=bytearray(n); idx=0
    for o in range(s):
        for j in range(o,n,s):
            out[idx]=p[j]; idx+=1
    return bytes(out)
def inter(plain,s):
    n=len(plain); out=bytearray(n); idx=0
    for o in range(s):
        for j in range(o,n,s):
            out[j]=plain[idx]; idx+=1
    return bytes(out)
def detransform(stored,e2):
    k=e2&7
    if k==0: return stored
    if k==2: return bytes((stored[i]-i)&0xff for i in range(len(stored)))
    if k==4: return stored[::-1]
    if k==5:
        o=bytearray(len(stored)); prev=0
        for i,b in enumerate(stored): o[i]=(b-prev)&0xff; prev=b
        return bytes(o)
    if k==3: return deinter(stored,STRIDES[(e2>>3)&3])
    return None  # kind1 unknown
def forward(plain,e2):
    k=e2&7
    if k==0: return plain
    if k==2: return bytes((plain[i]+i)&0xff for i in range(len(plain)))
    if k==4: return plain[::-1]
    if k==5:
        o=bytearray(len(plain)); acc=0
        for i,b in enumerate(plain): acc=(acc+b)&0xff; o[i]=acc
        return bytes(o)
    if k==3: return inter(plain,STRIDES[(e2>>3)&3])
    return None

# ---------- generators ----------
def lcg_stream(x0,nbytes):
    out=bytearray(); x=x0
    while len(out)<nbytes:
        out+=struct.pack('<Q',x); x=(LCG_A*x+LCG_C)&MASK64
    return bytes(out[:nbytes])

XS_MULT=0x2545F4914F6CDD1D; XS_MINV=pow(XS_MULT,-1,1<<64)
def _xs64(x):
    x^=x>>12; x&=MASK64; x^=(x<<25)&MASK64; x^=x>>27; return x&MASK64
def xs64star_stream(out0,nbytes):
    # out0 = first emitted 64-bit value; state = out0 * Minv (post-update state)
    out=bytearray(); s=(out0*XS_MINV)&MASK64
    while len(out)<nbytes:
        out+=struct.pack('<Q',(s*XS_MULT)&MASK64); s=_xs64(s)
    return bytes(out[:nbytes])

def ca_run_step_all(W,row,wrap):
    full=(1<<W)-1
    if wrap:
        L=((row<<1)|(row>>(W-1)))&full
        R=((row>>1)|((row&1)<<(W-1)))&full
    else:
        L=(row<<1)&full; R=(row>>1)
    masks=[]
    for pat in range(8):
        lb=(pat>>2)&1; cb=(pat>>1)&1; rb=pat&1
        masks.append(((L if lb else ~L)&(row if cb else ~row)&(R if rb else ~R))&full)
    return masks
def step_rule(masks,rule):
    new=0
    for pat in range(8):
        if (rule>>pat)&1: new|=masks[pat]
    return new

def ca_run(rule,W,rows,row0_int,wrap):
    full=(1<<W)-1
    row=row0_int & full
    outbits=[]
    for _ in range(rows):
        outbits.append(row)
        if wrap:
            L=((row<<1)|(row>>(W-1)))&full
            R=((row>>1)|((row&1)<<(W-1)))&full
        else:
            L=(row<<1)&full
            R=(row>>1)
        new=0
        # patterns of (l,c,r)
        for pat in range(8):
            if (rule>>pat)&1:
                lb=(pat>>2)&1; cb=(pat>>1)&1; rb=pat&1
                m=(L if lb else ~L)&(row if cb else ~row)&(R if rb else ~R)&full
                new|=m
        row=new
    # pack bits MSB-first into bytes: bit index 0 = MSB of first byte
    # each row is W bits, row's MSB is position W-1
    ba=bytearray()
    for rb in outbits:
        ba+=rb.to_bytes(W//8,'big')
    return bytes(ba)

_WFMT={1:'B',2:'<H',4:'<I'}
_WFMTS={2:'<h',4:'<i'}
_MK32=0xFFFFFFFF
def _mt_temper(y):
    y^=(y>>11); y^=(y<<7)&0x9D2C5680; y^=(y<<15)&0xEFC60000; y^=(y>>18); return y&_MK32
def _mt_undo_r(y,s):
    x=y
    for _ in range(32//s+1): x=y^(x>>s)
    return x&_MK32
def _mt_undo_l(y,s,m):
    x=y
    for _ in range(32//s+1): x=y^((x<<s)&m)
    return x&_MK32
def mt_untemper(y):
    y=_mt_undo_r(y,18); y=_mt_undo_l(y,15,0xEFC60000); y=_mt_undo_l(y,7,0x9D2C5680); y=_mt_undo_r(y,11); return y&_MK32
def _mt_regen(mt):
    for i in range(624):
        y=(mt[i]&0x80000000)|(mt[(i+1)%624]&0x7fffffff)
        mt[i]=mt[(i+397)%624]^(y>>1)
        if y&1: mt[i]^=0x9908B0DF
    return mt
def mt19937_stream(state624,nbytes):
    mt=list(state624); out=bytearray(); first=True
    while len(out)<nbytes:
        if not first: _mt_regen(mt)
        first=False
        for j in range(624):
            out+=struct.pack('<I',_mt_temper(mt[j]))
            if len(out)>=nbytes: break
    return bytes(out[:nbytes])

# ---- MT19937 tempered-output linear map: word[i+624]=L(word[i],word[i+1],word[i+397],word[i+398]) ----
_MTLN,_MTLM=624,397
_MT_B=None
def _mt_wle(p): return [int.from_bytes(p[j:j+4],'little') for j in range(0,len(p)//4*4,4)]
def _mt_fit(words):
    B=[None]*128
    for i in range(len(words)-_MTLN):
        q=words[i]|words[i+1]<<32|words[i+_MTLM]<<64|words[i+_MTLM+1]<<96; y=words[i+_MTLN]
        while q:
            b=q.bit_length()-1; v=B[b]
            if v is None: B[b]=(q,y); break
            q^=v[0]; y^=v[1]
        if None not in B: break
    return B
def _mt_L(B,a,b,c,d):
    q=a|b<<32|c<<64|d<<96; y=0
    while q:
        v=B[q.bit_length()-1]
        if v is None: return None
        q^=v[0]; y^=v[1]
    return y
def _mt_basis():
    global _MT_B
    if _MT_B is None:
        st=[(i*2654435761+12345)&0xffffffff for i in range(624)]
        _MT_B=_mt_fit(_mt_wle(mt19937_stream(st,1700*4)))
    return _MT_B
def mtlin_detect(payload):
    n=len(payload)
    if n%4 or n//4 < _MTLN+520: return None
    B=_mt_basis(); w=_mt_wle(payload); P=251
    D=[]
    for i in range(min(len(w)-_MTLN, 4*P)):
        v=_mt_L(B,w[i],w[i+1],w[i+_MTLM],w[i+_MTLM+1])
        if v is None: return None
        D.append(v^w[i+_MTLN])
    if not all(D[i]==D[i%P] for i in range(P,len(D))): return None
    Dp=D[:P]
    # full verify
    rec=w[:_MTLN]
    for i in range(len(w)-_MTLN):
        v=_mt_L(B,rec[i],rec[i+1],rec[i+_MTLM],rec[i+_MTLM+1])
        rec.append(v^Dp[i%P])
    if b''.join(x.to_bytes(4,'little') for x in rec)[:n]!=payload: return None
    return payload[:_MTLN*4]+b''.join(x.to_bytes(4,'little') for x in Dp)
def mtlin_reconstruct(param,length):
    B=_mt_basis()
    rec=_mt_wle(param[:_MTLN*4]); Dp=_mt_wle(param[_MTLN*4:_MTLN*4+251*4]); P=251
    nw=(length+3)//4
    while len(rec)<nw:
        i=len(rec)-_MTLN
        rec.append(_mt_L(B,rec[i],rec[i+1],rec[i+_MTLM],rec[i+_MTLM+1])^Dp[i%P])
    return b''.join(x.to_bytes(4,'little') for x in rec)[:length]

def vaneck_bytes(nvals,lead,W=2):
    # Van Eck sequence with a(0)=lead; values packed little-endian in W bytes (mod 2^(8W))
    out=bytearray(); last={}; cur=lead; m=(1<<(8*W))-1; f=_WFMT[W]
    for i in range(nvals):
        out+=struct.pack(f,cur & m)
        nxt=(i-last[cur]) if cur in last else 0
        last[cur]=i; cur=nxt
    return bytes(out)

def vaneck_seq(n,s):
    seq=[s]; last={}
    for i in range(n-1):
        p=seq[i]; seq.append(i-last[p] if p in last else 0); last[p]=i
    return seq
def recaman_bytes(num):
    u=bytearray((0).to_bytes(4,'little')); s={0}; c=0
    for k in range(1,num):
        x=c-k; c=x if (x>0 and x not in s) else c+k; s.add(c); u+=c.to_bytes(4,'little')
    return bytes(u)
def collatz_bytes(num):
    mm={1:0}; r=bytearray((0).to_bytes(4,'little'))
    for n in range(1,num):
        c=n; q=[]
        while c not in mm:
            q.append(c); c=c//2 if c%2==0 else 3*c+1
        b=mm[c]
        for j,v in enumerate(reversed(q)): mm[v]=b+j+1
        r+=mm[n].to_bytes(4,'little')
    return bytes(r)
def gen_linrec4(seed4,coeffs,n):
    # order-4 linear recurrence over 32-bit words: w[i+4]=(c0 w[i]+c1 w[i+1]+c2 w[i+2]+c3 w[i+3]) mod 2^32
    words=list(seed4); c0,c1,c2,c3=coeffs; nw=n//4
    for _ in range(nw-4):
        i=len(words)-4
        words.append((c0*words[i]+c1*words[i+1]+c2*words[i+2]+c3*words[i+3])&0xffffffff)
    return b''.join(w.to_bytes(4,'little') for w in words)
def _linrec4_coeffs(words):
    if len(words)<14: return None
    coeffs=[1,1,1,1]
    for B in range(1,32):
        nm=1<<(B+1); found=False
        for k0 in (0,1):
            for k1 in (0,1):
                for k2 in (0,1):
                    for k3 in (0,1):
                        cand=[(coeffs[0]+(k0<<B))%nm,(coeffs[1]+(k1<<B))%nm,(coeffs[2]+(k2<<B))%nm,(coeffs[3]+(k3<<B))%nm]
                        ok=True
                        for q in range(10):
                            if (cand[0]*words[q]+cand[1]*words[q+1]+cand[2]*words[q+2]+cand[3]*words[q+3])%nm!=words[q+4]%nm: ok=False; break
                        if ok: coeffs=cand; found=True; break
                    if found: break
                if found: break
            if found: break
        if not found: return None
    return coeffs
def linrec4_detect(plain,n):
    if n%4 or n<64: return None
    words=[int.from_bytes(plain[j:j+4],'little') for j in range(0,min(len(plain),400),4)]
    coeffs=_linrec4_coeffs(words)
    if coeffs is None: return None
    if gen_linrec4(words[:4],coeffs,n)==plain:
        return b''.join(w.to_bytes(4,'little') for w in words[:4])+b''.join(w.to_bytes(4,'little') for w in coeffs)
    return None
def linrec4_key_resolve(ct,Kc):
    """Given ciphertext and relative key Kc (up to global XOR const), find gc s.t. plaintext is a valid linrec4."""
    m=min(len(ct),600); base=bytes(ct[j]^Kc[j%QKEY] for j in range(m)); nw=m//4
    for gc in range(256):
        words=[int.from_bytes(bytes(base[4*w+t]^gc for t in range(4)),'little') for w in range(nw)]
        co=_linrec4_coeffs(words)
        if co is None: continue
        if all((co[0]*words[i]+co[1]*words[i+1]+co[2]*words[i+2]+co[3]*words[i+3])&0xffffffff==words[i+4] for i in range(4,nw-4)):
            return bytes(x^gc for x in Kc)
    return None

_PRIMEGAPS=None
def _primegaps():
    global _PRIMEGAPS
    if _PRIMEGAPS is None:
        N=2300000; v=bytearray([1])*N; v[0]=v[1]=0
        for i in range(2,1517):
            if v[i]: v[i*i:N:i]=bytearray(len(range(i*i,N,i)))
        pr=[i for i,x in enumerate(v) if x]
        _PRIMEGAPS=bytes(pr[j+1]-pr[j] for j in range(len(pr)-1))
    return _PRIMEGAPS
def gen_pg(off,n):
    return _primegaps()[off:off+n]
def primegap_key_resolve(ct):
    """Recover period-251 key for a masked prime-gap chunk by brute-forcing the gap offset (known-plaintext)."""
    g=_primegaps(); n=len(ct); Q=QKEY; maxoff=min(len(g)-n,20000)
    if maxoff<0: return None
    for off in range(maxoff):
        okk=True
        for t in range(32):
            if (ct[Q+t]^ct[t])!=(g[off+Q+t]^g[off+t]): okk=False; break
        if not okk: continue
        key=bytes(ct[r]^g[off+r] for r in range(Q))
        if gen_pg(off,n)==bytes(ct[j]^key[j%Q] for j in range(n)): return key
    return None
def primegap_detect(plain,n):
    if n<32: return None
    g=_primegaps(); head=plain[:32]
    # locate offset by first 32 gap bytes
    start=0
    while True:
        idx=g.find(head,start)
        if idx<0: return None
        if g[idx:idx+n]==plain: return idx.to_bytes(4,'big')
        start=idx+1
def a181_bits_bytes(val,n):
    num=(n-4)//3
    u=vaneck_seq(num*2+5,val); t=u[3:3+num*2+2]
    g=bytearray(b"\x00\x00\x00\x01" if val==0 else (val&0xffffffff).to_bytes(4,"little"))
    for k in range(num):
        g.extend([((t[2*k]&15)<<4)|((t[2*k-1]>>8)&15 if k else 0),(t[2*k]>>4)&255,t[2*k+1]&255])
    lt=t[num*2]; g.extend([((lt&15)<<4)|((t[num*2-1]>>8)&15),(lt>>4)&255])
    return bytes(g)

def vaneck_seeded_bytes(n,width,enc,startidx,seed,lead):
    fmt=('<%di'%n) if width==4 else ('<%dh'%n)
    VE=vaneck_seq(n+startidx+1,seed)
    tail=VE[startidx:startidx+(n-1)]
    if enc==1:  # delta-encoded
        vals=[lead,tail[0]]+[tail[i]-tail[i-1] for i in range(1,len(tail))]
    else:       # raw
        vals=[lead]+tail
    return struct.pack(fmt,*vals)

# ---------- container ----------
def parse(bindata):
    assert bindata[:11]==b'UNCLEJACKIE'
    hdr=bindata[:HDRLEN]; off=HDRLEN; chunks=[]
    while off+14<=len(bindata):
        length=struct.unpack('>I',bindata[off:off+4])[0]
        typ=bindata[off+4:off+8]; e1=bindata[off+8]; e2=bindata[off+9]
        payload=bindata[off+10:off+10+length]
        crc=struct.unpack('>I',bindata[off+10+length:off+14+length])[0]
        chunks.append((typ,e1,e2,length,payload,crc)); off+=14+length
    return hdr,chunks,off

def _detect(plain,length):
    """Type-agnostic exact generator detection with cheap pre-checks. Returns (mid,param) or (0,None)."""
    # PRNG: LCG / xorshift64*
    if length%8==0 and length>=16:
        x0=struct.unpack('<Q',plain[:8])[0]
        hp=plain[:64]
        if lcg_stream(x0,64)==hp and lcg_stream(x0,length)==plain: return 1,plain[:8]
        if xs64star_stream(x0,64)==hp and xs64star_stream(x0,length)==plain: return 5,plain[:8]
    # CA elementary CA (width 2048)
    W=2048
    if (length*8)%W==0 and length>=2*(W//8):
        rows=length*8//W
        row0=int.from_bytes(plain[:W//8],'big'); row1=int.from_bytes(plain[W//8:2*(W//8)],'big')
        for wrap in (0,1):
            one=ca_run_step_all(W,row0,wrap)
            for rule in range(256):
                if step_rule(one,rule)==row1:
                    if ca_run(rule,W,rows,row0,wrap)==plain:
                        return 2, bytes([rule,wrap])+struct.pack('>H',W)+plain[:W//8]
    # Van Eck (width 2/4/1, short literal prefix K)
    if length>=4:
        for W in (2,4,1):
            if length%W: continue
            nv=length//W; f=_WFMT[W]
            for K in range(0,3):
                if K>=nv: break
                lead=struct.unpack(f,plain[W*K:W*K+W])[0]
                if vaneck_bytes(min(nv-K,128),lead,W)==plain[W*K:W*K+W*min(nv-K,128)] and plain[W*K:]==vaneck_bytes(nv-K,lead,W):
                    return 3, bytes([W,K])+plain[:W*K]+struct.pack(f,lead)
        # seeded Van Eck, delta/raw, 16/32-bit signed
        for width in (4,2):
            if length%width: continue
            n=length//width
            if n<2: continue
            lead=struct.unpack(_WFMTS[width],plain[:width])[0]
            for enc,startidx,seed in [(1,2,-lead),(0,2,-lead),(1,2,abs(lead)),(1,1,-lead),(1,0,-lead),(0,0,-lead),(1,2,lead)]:
                try:
                    head=vaneck_seeded_bytes(min(n,256),width,enc,startidx,seed,lead)
                    if head!=plain[:len(head)]: continue
                    if vaneck_seeded_bytes(n,width,enc,startidx,seed,lead)==plain:
                        return 7, bytes([width,enc,startidx])+struct.pack('<i',seed)+struct.pack(_WFMTS[width],lead)
                except (struct.error,OverflowError): pass
    # MT19937
    if length%4==0 and length>=624*4*2:
        w=struct.unpack('<%dI'%(length//4),plain[:length//4*4])
        state=[mt_untemper(x) for x in w[:624]]
        scr=min(length,2496+1024)  # divergence (if any) appears at/after word 624
        if mt19937_stream(state,scr)==plain[:scr] and mt19937_stream(state,length)==plain:
            return 6, b''.join(struct.pack('<I',x) for x in state)
    # sha256 chain
    if length%32==0 and length>=64:
        import hashlib
        cur=plain[:32]
        if hashlib.sha256(cur).digest()==plain[32:64]:
            rebuilt=bytearray(cur)
            for _ in range(length//32-1):
                cur=hashlib.sha256(cur).digest(); rebuilt+=cur
            if bytes(rebuilt)==plain: return 4, plain[:32]
    # Recaman / Collatz (parameterless, from length; 4-byte LE, starts 0)
    if length%4==0 and length>=8 and plain[:4]==b'\x00\x00\x00\x00':
        num=length//4
        if recaman_bytes(min(num,64))==plain[:min(num,64)*4] and recaman_bytes(num)==plain:
            return 10, b''
        if collatz_bytes(min(num,64))==plain[:min(num,64)*4] and collatz_bytes(num)==plain:
            return 11, b''
    # CNST: binary fractional digits of sqrt(2/3/5/7)
    if 8<=length<=200000:
        import math as _m
        for e0 in range(4):
            Nh=24
            xh=(_m.isqrt((2,3,5,7)[e0]<<(16*Nh))%(1<<(8*Nh))).to_bytes(Nh,'big')
            if xh[:8]!=plain[:8]: continue
            N=length+4
            x=(_m.isqrt((2,3,5,7)[e0]<<(16*N))%(1<<(8*N))).to_bytes(N,'big')[:length]
            if x==plain:
                return 12, bytes([e0])
    # A181 bit-packed Van Eck (output length = 6 + 3*((n-4)//3) == n requires n%3==0)
    if length>=10 and length%3==0:
        for val in range(0,16):
            try:
                head=a181_bits_bytes(val,min(length,304)); hl=len(head)-2
                if head[:hl]!=plain[:hl]: continue
                if a181_bits_bytes(val,length)==plain:
                    return 9, struct.pack('<I',val)
            except Exception: pass
    # SEQ2: order-4 32-bit linear recurrence
    if length%4==0 and length>=64:
        r=linrec4_detect(plain,length)
        if r is not None: return 15,r
    # SEQ2: consecutive prime gaps
    r=primegap_detect(plain,length)
    if r is not None: return 16,r
    return 0,None

def _ramp_sub(plain):
    return bytes((plain[i]-i)&0xff for i in range(len(plain)))
def _ramp_add(base):
    return bytes((base[i]+i)&0xff for i in range(len(base)))
_CLR_LSB=bytes(i&0xFE for i in range(256))
_SET_LSB=bytes(i&1 for i in range(256))
_BITEXP=[bytes((v>>k)&1 for k in range(8)) for v in range(256)]
def _pack_lsb(p):
    n=len(p); out=bytearray((n+7)//8)
    for i in range(n):
        if p[i]&1: out[i>>3]|=1<<(i&7)
    return bytes(out)

def _reconstruct(mid,param,length):
    if mid==1:
        return lcg_stream(struct.unpack('<Q',param)[0],length)
    if mid==5:
        return xs64star_stream(struct.unpack('<Q',param)[0],length)
    if mid==2:
        rule=param[0]; wrap=param[1]; W=struct.unpack('>H',param[2:4])[0]; row0=int.from_bytes(param[4:4+W//8],'big')
        return ca_run(rule,W,length*8//W,row0,wrap)
    if mid==3:
        W=param[0]; K=param[1]; prefix=param[2:2+W*K]; lead=struct.unpack(_WFMT[W],param[2+W*K:2+W*K+W])[0]
        return prefix+vaneck_bytes(length//W-K,lead,W)
    if mid==4:
        import hashlib; cur=param; parts=bytearray(cur)
        for _ in range(length//32-1): cur=hashlib.sha256(cur).digest(); parts+=cur
        return bytes(parts)
    if mid==6:
        return mt19937_stream(list(struct.unpack('<624I',param)),length)
    if mid==7:
        width=param[0]; enc=param[1]; startidx=param[2]; seed=struct.unpack('<i',param[3:7])[0]
        lead=struct.unpack(_WFMTS[width],param[7:7+width])[0]
        return vaneck_seeded_bytes(length//width,width,enc,startidx,seed,lead)
    if mid==8:
        return _ramp_add(_reconstruct(param[0],param[1:],length))
    if mid==9:
        return a181_bits_bytes(struct.unpack('<I',param)[0],length)
    if mid==10:
        return recaman_bytes(length//4)
    if mid==11:
        return collatz_bytes(length//4)
    if mid==12:
        import math as _m
        e0=param[0]; N=length+4
        return (_m.isqrt((2,3,5,7)[e0]<<(16*N))%(1<<(8*N))).to_bytes(N,'big')[:length]
    if mid==14:
        return mtlin_reconstruct(param,length)
    if mid==15:
        seed4=list(struct.unpack('<4I',param[:16])); coeffs=list(struct.unpack('<4I',param[16:32]))
        return gen_linrec4(seed4,coeffs,length)
    if mid==16:
        off=int.from_bytes(param[:4],'big'); return gen_pg(off,length)
    raise ValueError("bad mid %d"%mid)

def try_model(typ,e1,e2,length,payload):
    """return (model_id, param_bytes) or (0,None). Must verify exact vs payload."""
    plain=detransform(payload,e2)
    if plain is None:
        # kind-1 (unknown transform / no key): try MT19937 linear model on raw ciphertext
        if typ==b'MTST':
            r=mtlin_detect(payload)
            if r is not None: return 14, r
        return 0,None
    mid,param=_detect(plain,length)
    if mid: return mid,param
    # ramp + generator (e.g. DUP): plain[i] = (base[i] + i) & 255
    base=_ramp_sub(plain)
    smid,sparam=_detect(base,length)
    if smid: return 8, bytes([smid])+sparam
    return 0,None

import zlib as _zlib
_FSPECS=[('none',),('stride',3),('stride',4),
         ('delta',1),('delta',2),('delta',3),('delta',4),
         ('lane',2),('lane',3),('lane',4),
         ('xor',1),('xor',2),('xor',3),('xor',4),
         ('laned',3),('laned',4),
         ('delta',640),('delta',1024),('delta',1280),('delta',2048)]
def _plane_delta(pl):
    o=bytearray(len(pl)); prev=0
    for i,x in enumerate(pl): o[i]=(x-prev)&0xff; prev=x
    return bytes(o)
def _plane_undelta(pl):
    o=bytearray(len(pl)); acc=0
    for i,x in enumerate(pl): acc=(acc+x)&0xff; o[i]=acc
    return bytes(o)
def _lane(b,w): return b"".join(b[i::w] for i in range(w))
def _unlane(b,w,n):
    out=bytearray(n); q=0
    for i in range(w):
        m=len(range(i,n,w)); out[i::w]=b[q:q+m]; q+=m
    return bytes(out)
def apply_filter(b,fid):
    sp=_FSPECS[fid]; t=sp[0]
    if t=='none': return b
    if t=='stride':
        s=sp[1]; out=bytearray()
        for i in range(s): out+=_plane_delta(b[i::s])
        return bytes(out)
    if t=='delta':
        L=sp[1]; return bytes(b[:L])+bytes((b[i]-b[i-L])&255 for i in range(L,len(b)))
    if t=='xor':
        L=sp[1]; return bytes(b[:L])+bytes((b[i]^b[i-L]) for i in range(L,len(b)))
    if t=='laned':
        return _plane_delta(_lane(b,sp[1]))
    return _lane(b,sp[1])
def unapply_filter(b,fid,n):
    sp=_FSPECS[fid]; t=sp[0]
    if t=='none': return b
    if t=='stride':
        s=sp[1]; sizes=[(n-i+s-1)//s for i in range(s)]; planes=[]; pos=0
        for sz in sizes: planes.append(_plane_undelta(b[pos:pos+sz])); pos+=sz
        out=bytearray(n)
        for i in range(s): out[i::s]=planes[i]
        return bytes(out)
    if t=='delta':
        L=sp[1]; out=bytearray(b)
        for i in range(L,n): out[i]=(b[i]+out[i-L])&255
        return bytes(out)
    if t=='xor':
        L=sp[1]; out=bytearray(b)
        for i in range(L,n): out[i]=(b[i]^out[i-L])
        return bytes(out)
    if t=='laned':
        return _unlane(_plane_undelta(b),sp[1],n)
    return _unlane(b,sp[1],n)
def _dref_apply(p,r,op):
    n=len(p)
    if op==1: return bytes(p[i]^r[i] for i in range(n))
    if op==3: return bytes((r[i]-p[i])&0xff for i in range(n))
    return bytes((p[i]-r[i])&0xff for i in range(n))
def _dref_undo(d,r,op):
    n=len(d)
    if op==1: return bytes(d[i]^r[i] for i in range(n))
    if op==3: return bytes((r[i]-d[i])&0xff for i in range(n))
    return bytes((d[i]+r[i])&0xff for i in range(n))
def choose_filter(b):
    if len(b)<64: return 0,b
    # fast proxy on a prefix to rank filters
    probe=b[:24576]
    scored=[(len(_zlib.compress(probe if fid==0 else apply_filter(probe,fid),1)),fid) for fid in range(len(_FSPECS))]
    scored.sort()
    best_fid=scored[0][1]
    # for large buffers, confirm the top proxy candidates with a real lzma measure on the full buffer
    if len(b)>=100000:
        cand=[]
        for _,fid in scored[:5]:
            if fid not in cand: cand.append(fid)
        bc=None
        for fid in cand:
            fb=b if fid==0 else apply_filter(b,fid)
            cc=len(lzma.compress(fb,preset=4))
            if bc is None or cc<bc: bc=cc; best_fid=fid
    return best_fid,(b if best_fid==0 else apply_filter(b,best_fid))

QKEY=251
def km_unmask(ct,key):
    kp=(key*(len(ct)//QKEY+1))[:len(ct)]
    return bytes(x^y for x,y in zip(ct,kp))
def km_mask(pt,key):  # same op (xor); ct = pt ^ key_repeated
    return km_unmask(pt,key)
def km_modal(ct):
    import collections
    cols=[collections.Counter() for _ in range(QKEY)]
    for i,b in enumerate(ct): cols[i%QKEY][b]+=1
    return bytes(c.most_common(1)[0][0] for c in cols)
def km_lcg_lowbyte(ct):
    n=len(ct); nwords=n//8
    if nwords<4*QKEY: return None
    a_lo,c_lo=LCG_A&0xFF,LCG_C&0xFF
    for g in range(256):
        s=g; km={}; ok=True
        for i in range(nwords):
            kb=ct[8*i]^s; pos=(8*i)%QKEY
            if pos in km:
                if km[pos]!=kb: ok=False; break
            else: km[pos]=kb
            s=(a_lo*s+c_lo)&0xFF
        if ok and len(km)==QKEY:
            key=bytes(km[p] for p in range(QKEY)); pt=km_unmask(ct,key)
            if lcg_stream(struct.unpack('<Q',pt[:8])[0],n)==pt: return key
    return None
def _entropy(b):
    import collections,math as _m
    if not b: return 0.0
    c=collections.Counter(b); n=len(b)
    return -sum(v/n*_m.log2(v/n) for v in c.values())
def _wht(a):
    h=1
    while h<256:
        for i in range(0,256,h*2):
            for j in range(i,i+h):
                x=a[j]; y=a[j+h]; a[j]=x+y; a[j+h]=x-y
        h*=2
def km_ml_prior(cts,logp,cap=600):
    """Per-residue max-likelihood repeating-XOR key. cts: list of ciphertext bytes; logp: 256 log-probs."""
    key=bytearray(QKEY)
    for r in range(QKEY):
        col=bytearray()
        for ct in cts:
            col+=ct[r::QKEY][:cap]
        if not col: continue
        # histogram then score each k via table lookup
        hist=[0]*256
        for b in col: hist[b]+=1
        nz=[(b,hist[b]) for b in range(256) if hist[b]]
        best=None
        for k in range(256):
            s=0.0
            for b,h in nz: s+=h*logp[b^k]
            if best is None or s>best[0]: best=(s,k)
        key[r]=best[1]
    return bytes(key)
def km_rel_key(cts,lag):
    """Differential relative-key: recover period-251 key up to a global XOR constant from ct[j]^ct[j+lag] modes."""
    votes=[None]*QKEY
    for ct in cts:
        nb=min(len(ct),100000)
        for j in range(nb-lag):
            a=j%QKEY; v=votes[a]
            if v is None: v=votes[a]=[0]*256
            v[ct[j]^ct[j+lag]]+=1
    rel=[]
    for a in range(QKEY):
        if votes[a]:
            v=votes[a]; m=max(range(256),key=lambda x:v[x]); rel.append((a,(a+lag)%QKEY,m))
    Kc=[None]*QKEY; Kc[0]=0; changed=True
    while changed:
        changed=False
        for a,b,m in rel:
            if Kc[a] is not None and Kc[b] is None: Kc[b]=Kc[a]^m; changed=True
            elif Kc[b] is not None and Kc[a] is None: Kc[a]=Kc[b]^m; changed=True
    if any(x is None for x in Kc): return None
    return bytes(Kc)
def km_ml(hp,hc):
    """Walsh-Hadamard max-likelihood repeating-XOR key. hp: 256 prior counts; hc: 251x256 per-pos counts."""
    import math as _m
    tot=sum(hp)+1e-9
    wlp=[_m.log((hp[b]+0.5)/(tot+128.0)) for b in range(256)]
    _wht(wlp)
    key=bytearray(QKEY)
    for j in range(QKEY):
        h=[float(x) for x in hc[j]]
        if not any(h): continue
        _wht(h)
        for b in range(256): h[b]*=wlp[b]
        _wht(h)
        best=0; bk=0
        for k in range(256):
            if h[k]>best or k==0:
                if h[k]>best: best=h[k]; bk=k
        key[j]=bk
    return bytes(key)
def recover_group_keys(chunks):
    """Return {(typ,e2,length): key251} for kind-1 groups where a helpful key was recovered."""
    import collections
    groups=collections.defaultdict(list)
    sibs=collections.defaultdict(list)
    for idx,c in enumerate(chunks):
        if (c[2]&7)==1: groups[(c[0],c[2],c[3])].append(idx)
        else: sibs[(c[0],c[3])].append(idx)
    keys={}
    for gk,idxs in groups.items():
        typ,e2,length=gk
        key=None
        for i in idxs:
            key=km_lcg_lowbyte(chunks[i][4])
            if key: break
        if key is None:
            cand=[km_modal(chunks[i][4]) for i in idxs]
            # per-residue ML using same-type (any length) plaintext as language-model prior
            import math as _mm
            styp=[si for (st,sl),slist in sibs.items() if st==typ for si in slist]
            hpc=[0]*256
            for si in styp:
                pl=detransform(chunks[si][4],chunks[si][2])
                if pl:
                    for b in pl[:8192]: hpc[b]+=1
            tt=sum(hpc)
            # gate: only run the (costly) per-residue ML for text-like priors (top-16 mass > 0.4)
            top16=sum(sorted(hpc,reverse=True)[:16])
            if tt and top16>0.4*tt:
                logp=[_mm.log((hpc[b]+0.5)/(tt+128.0)) for b in range(256)]
                cand.append(km_ml_prior([chunks[i][4] for i in idxs],logp))
            # ml_key using non-kind1 sibling byte-distribution as prior
            sib=sibs.get((typ,length),[])
            if sib:
                hp=[0]*256
                for si in sib:
                    pl=detransform(chunks[si][4],chunks[si][2])
                    if pl:
                        for b in pl[:4096]: hp[b]+=1
                if sum(hp):
                    hc=[[0]*256 for _ in range(QKEY)]
                    for i in idxs:
                        ct=chunks[i][4]
                        for j in range(min(len(ct),QKEY*400)): hc[j%QKEY][ct[j]]+=1
                    cand.append(km_ml(hp,hc))
            # prime-gap masked chunk: recover key by known-plaintext offset brute
            if typ==b'SEQ2':
                pk=primegap_key_resolve(chunks[idxs[0]][4])
                if pk is not None: key=pk
            # differential relative-key attack â only for hard, non-clean-generator types
            if key is None and typ in (b'IMG ',b'WAVE',b'SEQ2',b'SPRS',b'LOGS'):
                cts=[chunks[i][4] for i in idxs]
                lags=(1,2,3,4)
                for lag in lags:
                    Kc=km_rel_key(cts,lag)
                    if Kc is None: continue
                    if typ==b'SEQ2':
                        rk=linrec4_key_resolve(cts[0],Kc)
                        if rk is not None: key=rk; break
                    # resolve global const by prefix compressibility (text/structured plaintexts)
                    s0=cts[0][:1536]; bg=None
                    for gc in range(256):
                        z=len(_zlib.compress(km_unmask(s0,bytes(x^gc for x in Kc)),1))
                        if bg is None or z<bg[0]: bg=(z,gc)
                    cand.append(bytes(x^bg[1] for x in Kc))
        if key is None:
            # pick the key that makes the group most compressible (fast prefix proxy)
            W=24576
            base=sum(len(_zlib.compress(chunks[i][4][:W],1)) for i in idxs)
            best=None
            for k in cand:
                sc=sum(len(_zlib.compress(km_unmask(chunks[i][4][:W],k),1)) for i in idxs)
                if best is None or sc<best[0]: best=(sc,k)
            if best and best[0]<base*0.92: key=best[1]
        if key is not None: keys[gk]=key
    return keys

import re as _re
_L0RE=_re.compile(r'^(\d+) (\d+)\.(\d+)\.(\d+)\.(\d+) "(\w+) (/[^?"]*)\?id=(\d+)" (\d+) (\d+) (\d+)ms "([^/]+)/([^ ]+) \(([^)]*)\)"$')
_L1RE=_re.compile(r'^(\d+),(\d+)\.(\d+)\.(\d+)\.(\d+),([^,]*),([^,]*),([^,]*)$')
def _vi(n,o):
    while True:
        b=n&127; n>>=7; o.append(b|128 if n else b)
        if not n: return
def _vr(b,p):
    n=0; sh=0
    while True:
        c=b[p]; p+=1; n|=(c&127)<<sh
        if not c&128: return n,p
        sh+=7
def _zvi(x,o): _vi((x<<1) if x>=0 else ((-x<<1)-1),o)
def _zvr(b,p):
    v,p=_vr(b,p); return ((v>>1) if not v&1 else -((v+1)>>1)),p
def _en_dic(vals,o):
    dic=sorted(set(vals)); o2={v:i for i,v in enumerate(dic)}; _vi(len(dic),o)
    for v in dic:
        w=v.encode('latin1'); _vi(len(w),o); o+=w
    for v in vals: _vi(o2[v],o)
def _de_dic(b,p,k):
    n,p=_vr(b,p); dic=[]
    for _ in range(n):
        L,p=_vr(b,p); dic.append(b[p:p+L].decode('latin1')); p+=L
    vals=[]
    for _ in range(k):
        i,p=_vr(b,p); vals.append(dic[i])
    return vals,p
def _lsplit(text,rx):
    lines=text.split('\n'); tail=lines.pop() if lines and lines[-1]=='' else None
    rec=[]; exc=[]
    for i,L in enumerate(lines):
        m=rx.match(L)
        if m: rec.append((i,m.groups()))
        else: exc.append((i,L))
    if not rec or len(rec)*1000<len(lines)*997: return None
    return lines,tail,rec,exc
def _lhead(o,n,rec,exc,tail):
    _vi(n,o); mask=bytearray((n+7)//8)
    for i,_ in rec: mask[i>>3]|=1<<(i&7)
    o+=mask; _vi(len(exc),o)
    for i,L in exc:
        _vi(i,o); w=L.encode('latin1'); _vi(len(w),o); o+=w
    o.append(1 if tail is not None else 0)
def _ltail(buf,p):
    n,p=_vr(buf,p); mask=buf[p:p+(n+7)//8]; p+=(n+7)//8; ne,p=_vr(buf,p); exc={}
    for _ in range(ne):
        i,p=_vr(buf,p); L,p=_vr(buf,p); exc[i]=buf[p:p+L].decode('latin1'); p+=L
    tl=buf[p]; p+=1
    ok=[j for j in range(n) if mask[j>>3]&(1<<(j&7))]
    return n,exc,ok,p,tl
def _lfinish(n,exc,out,tail):
    if tail: out.append('')
    return '\n'.join(out)
def logs0_pack(text):
    sp=_lsplit(text,_L0RE)
    if sp is None: return None
    lines,tail,rec,exc=sp; o=bytearray(); _lhead(o,len(lines),rec,exc,tail); prev=0
    for _,g in rec: v=int(g[0]); _zvi(v-prev,o); prev=v
    for c in range(1,5):
        for _,g in rec: _vi(int(g[c]),o)
    _en_dic([g[5] for _,g in rec],o); _en_dic([g[6] for _,g in rec],o)
    for _,g in rec: _vi(int(g[7]),o)
    _en_dic([g[8] for _,g in rec],o); _en_dic([g[9] for _,g in rec],o)
    for _,g in rec: _vi(int(g[10]),o)
    for c in (11,12,13): _en_dic([g[c] for _,g in rec],o)
    return bytes(o)
def logs0_unpack(buf):
    n,exc,ok,p,tl=_ltail(buf,0); k=len(ok); ts=[]; prev=0
    for _ in range(k): v,p=_zvr(buf,p); prev+=v; ts.append(prev)
    cols=[]
    for _ in range(4):
        col=[]
        for _ in range(k): v,p=_vr(buf,p); col.append(v)
        cols.append(col)
    me,p=_de_dic(buf,p,k); pa,p=_de_dic(buf,p,k); q=[]
    for _ in range(k): v,p=_vr(buf,p); q.append(v)
    st,p=_de_dic(buf,p,k); sz,p=_de_dic(buf,p,k); ms=[]
    for _ in range(k): v,p=_vr(buf,p); ms.append(v)
    g1,p=_de_dic(buf,p,k); g2,p=_de_dic(buf,p,k); g3,p=_de_dic(buf,p,k); out=[]; r=0
    for i in range(n):
        if i in exc: out.append(exc[i])
        else:
            out.append('%d %d.%d.%d.%d "%s %s?id=%d" %s %s %dms "%s/%s (%s)"'%(ts[r],cols[0][r],cols[1][r],cols[2][r],cols[3][r],me[r],pa[r],q[r],st[r],sz[r],ms[r],g1[r],g2[r],g3[r])); r+=1
    return _lfinish(n,exc,out,tl)
def logs1_pack(text):
    sp=_lsplit(text,_L1RE)
    if sp is None: return None
    lines,tail,rec,exc=sp; o=bytearray(); _lhead(o,len(lines),rec,exc,tail); prev=0
    for _,g in rec: v=int(g[0]); _zvi(v-prev,o); prev=v
    for c in range(1,5):
        for _,g in rec: _vi(int(g[c]),o)
    _en_dic([g[5] for _,g in rec],o)
    # col6 (va): decimal with exactly 3 fractional digits -> int(v*1000) as fixed 3-byte LE
    def _va3(g6):
        if '.' not in g6: return None
        a,b=g6.rsplit('.',1)
        if len(b)!=3 or not a.isdigit() or a!=str(int(a)): return None
        iv=int(a)*1000+int(b)
        return iv if iv<(1<<24) else None
    if all(_va3(g[6]) is not None for _,g in rec):
        o.append(1)
        for _,g in rec:
            o+=_va3(g[6]).to_bytes(3,'little')
    else:
        o.append(0); _en_dic([g[6] for _,g in rec],o)
    _en_dic([g[7] for _,g in rec],o)
    return bytes(o)
def logs1_unpack(buf):
    n,exc,ok,p,tl=_ltail(buf,0); k=len(ok); ts=[]; prev=0
    for _ in range(k): v,p=_zvr(buf,p); prev+=v; ts.append(prev)
    ip=[]
    for _ in range(4):
        col=[]
        for _ in range(k): v,p=_vr(buf,p); col.append(v)
        ip.append(col)
    me,p=_de_dic(buf,p,k)
    vamode=buf[p]; p+=1
    if vamode==1:
        va=[]
        for _ in range(k):
            iv=int.from_bytes(buf[p:p+3],'little'); p+=3
            va.append('%d.%03d'%(iv//1000,iv%1000))
    else:
        va,p=_de_dic(buf,p,k)
    fl,p=_de_dic(buf,p,k); out=[]; r=0
    for i in range(n):
        if i in exc: out.append(exc[i])
        else:
            out.append('%d,%d.%d.%d.%d,%s,%s,%s'%(ts[r],ip[0][r],ip[1][r],ip[2][r],ip[3][r],me[r],va[r],fl[r])); r+=1
    return _lfinish(n,exc,out,tl)
_WORDRE=_re.compile(r'^([a-z]+ )*[a-z]+\.$')
def logs_wordtext_ok(text):
    """True if text is space-separated lowercase words, lines ending '.', last line may be truncated."""
    if not text: return False
    lines=text.split('\n')
    if text.endswith('\n'):
        comp=lines[:-1]; tail=''
    else:
        comp=lines[:-1]; tail=lines[-1]
    if not comp: return False
    for L in comp:
        if not _WORDRE.match(L): return False
    # tail (if any) must be a valid prefix of a word-line: only [a-z ] and optional trailing '.'
    if tail:
        t=tail[:-1] if tail.endswith('.') else tail
        if not _re.match(r'^([a-z]+ )*[a-z]*$', t): return False
    return comp,tail
def logs2_pack(text,widx):
    r=logs_wordtext_ok(text)
    if not r: return None
    comp,tail=r
    # mode: 0=ends after last complete line's newline (text endswith '\n', no tail)
    #       1=has partial tail after last newline (tail may be '' only if no comp)
    endnl=text.endswith('\n')
    o=bytearray(); o.append(0 if endnl else 1); _vi(len(comp),o)
    for L in comp:
        ws=L[:-1].split(' ')
        _vi(len(ws),o)
        for w in ws:
            i=widx.get(w)
            if i is None: return None
            _vi(i,o)
    if not endnl:
        tb=tail.encode('latin1'); _vi(len(tb),o); o+=tb
    return bytes(o)
def logs2_unpack(buf,vocab):
    p=0; mode=buf[p]; p+=1; nc,p=_vr(buf,p); out=[]
    for _ in range(nc):
        nw,p=_vr(buf,p); ws=[]
        for _ in range(nw):
            i,p=_vr(buf,p); ws.append(vocab[i])
        out.append(' '.join(ws)+'.')
    body='\n'.join(out)
    if mode==0:
        return body+'\n'
    tl,p=_vr(buf,p); tail=buf[p:p+tl].decode('latin1'); p+=tl
    if out: return body+'\n'+tail
    return tail
_LOGS_PACK={0:logs0_pack,1:logs1_pack}; _LOGS_UNPACK={0:logs0_unpack,1:logs1_unpack}

# ---- LOGS columnar: pack many LOGS bases into shared per-column streams ----
def _logs_classify(txt):
    if _lsplit(txt,_L0RE): return 0
    if _lsplit(txt,_L1RE): return 1
    if logs_wordtext_ok(txt): return 2
    return -1
def _lp(b):
    o=bytearray(); _vi(len(b),o); o+=b; return bytes(o)
def _lr(b,p):
    n,p=_vr(b,p); return b[p:p+n],p+n
def _de_dic_k(b,p,k):
    n,p=_vr(b,p); dic=[]
    for _ in range(n):
        L,p=_vr(b,p); dic.append(b[p:p+L].decode('latin1')); p+=L
    vals=[]
    for _ in range(k):
        i,p=_vr(b,p); vals.append(dic[i])
    return vals,p
def logs_col_pack(bases,widx):
    """Pack a list of LOGS base texts (bytes) into one columnar blob. All must classify to 0/1/2."""
    hdrs=bytearray()
    L0v=__import__('collections').defaultdict(list); L1v=__import__('collections').defaultdict(list)
    L0ts=[];L1ts=[]
    for base in bases:
        txt=base.decode('latin1'); fmt=_logs_classify(txt)
        o=bytearray(); o.append(fmt)
        if fmt in (0,1):
            rx=_L0RE if fmt==0 else _L1RE
            sp=_lsplit(txt,rx); lines,tail,rec,exc=sp
            _lhead(o,len(lines),rec,exc,tail); _vi(len(rec),o)
            if fmt==0:
                L0ts.append([int(g[0]) for _,g in rec])
                for _,g in rec:
                    for c in range(1,5): L0v['ip%d'%c].append(int(g[c]))
                    L0v['method'].append(g[5]); L0v['path'].append(g[6]); L0v['id'].append(int(g[7]))
                    L0v['status'].append(g[8]); L0v['size'].append(g[9]); L0v['ms'].append(int(g[10]))
                    L0v['uan'].append(g[11]); L0v['uav'].append(g[12]); L0v['uap'].append(g[13])
            else:
                L1ts.append([int(g[0]) for _,g in rec])
                for _,g in rec:
                    for c in range(1,5): L1v['ip%d'%c].append(int(g[c]))
                    L1v['metric'].append(g[5])
                    a,b=g[6].rsplit('.',1); L1v['va'].append(int(a)*1000+int(b))
                    L1v['flag'].append(g[7])
        else:
            o+=logs2_pack(txt,widx)
        hdrs+=_lp(bytes(o))
    def emit_ts(tslist,zz):
        b=bytearray()
        for ts in tslist:
            _vi(ts[0],b)
            for i in range(1,len(ts)):
                if zz: _zvi(ts[i]-ts[i-1],b)
                else: b.append(ts[i]-ts[i-1]-1000)
        return bytes(b)
    L0blk=bytearray(); L0blk+=_lp(emit_ts(L0ts,True))
    for c in range(1,5): L0blk+=_lp(bytes(L0v['ip%d'%c]))
    for col in ['method','path','status','size','uan','uav','uap']:
        b=bytearray(); _en_dic(L0v[col],b); L0blk+=_lp(bytes(b))
    # id: 3-byte LE, byte-plane split (stride 3); ids are ~20-bit uniform, MSB plane ~const
    _b3=b"".join(v.to_bytes(3,'little') for v in L0v['id'])
    L0blk+=_lp(b"".join(_b3[t::3] for t in range(3)))
    b=bytearray()
    for v in L0v['ms']: _vi(v,b)
    L0blk+=_lp(bytes(b))
    L1blk=bytearray(); L1blk+=_lp(emit_ts(L1ts,False))
    for c in range(1,5): L1blk+=_lp(bytes(L1v['ip%d'%c]))
    b=bytearray()  # metric: vocab-index varint (all metrics are vocab words)
    for m in L1v['metric']: _vi(widx[m],b)
    L1blk+=_lp(bytes(b))
    b=bytearray()
    for v in L1v['va']: b+=v.to_bytes(3,'little')
    L1blk+=_lp(bytes(b))
    b=bytearray(); _en_dic(L1v['flag'],b); L1blk+=_lp(bytes(b))
    out=bytearray(); _vi(len(bases),out)
    out+=_lp(bytes(hdrs)); out+=_lp(bytes(L0blk)); out+=_lp(bytes(L1blk))
    return bytes(out)
def logs_col_unpack(blob,vocab):
    p=0; nb,p=_vr(blob,p)
    hdrs,p=_lr(blob,p); L0blk,p=_lr(blob,p); L1blk,p=_lr(blob,p)
    hp=0; metas=[]
    for _ in range(nb):
        hlen,hp=_vr(hdrs,hp); metas.append(hdrs[hp:hp+hlen]); hp+=hlen
    parsed=[]; tot0=0;tot1=0
    for m in metas:
        fmt=m[0]; mp=1
        if fmt in (0,1):
            n,exc,ok,mp,tl=_ltail(m,mp); nrec,mp=_vr(m,mp)
            parsed.append((fmt,n,exc,tl,nrec))
            if fmt==0: tot0+=nrec
            else: tot1+=nrec
        else:
            parsed.append((2,m[1:]))
    def rd_blocks(blk):
        out=[]; pp=0
        while pp<len(blk):
            b,pp=_lr(blk,pp); out.append(b)
        return out
    L0b=rd_blocks(L0blk); L1b=rd_blocks(L1blk)
    def dec_ts(b,counts,zz):
        pp=0; res=[]
        for cnt in counts:
            if cnt==0: res.append([]); continue
            v,pp=_vr(b,pp); ts=[v]
            for _ in range(cnt-1):
                if zz: d,pp=_zvr(b,pp); ts.append(ts[-1]+d)
                else: ts.append(ts[-1]+b[pp]+1000); pp+=1
            res.append(ts)
        return res
    l0counts=[pr[4] for pr in parsed if pr[0]==0]
    l1counts=[pr[4] for pr in parsed if pr[0]==1]
    l0ts=dec_ts(L0b[0],l0counts,True); l1ts=dec_ts(L1b[0],l1counts,False)
    i=1
    ip0=[list(L0b[i+c]) for c in range(4)]; i+=4
    method,_=_de_dic_k(L0b[i],0,tot0); i+=1
    path,_=_de_dic_k(L0b[i],0,tot0); i+=1
    status,_=_de_dic_k(L0b[i],0,tot0); i+=1
    size,_=_de_dic_k(L0b[i],0,tot0); i+=1
    uan,_=_de_dic_k(L0b[i],0,tot0); i+=1
    uav,_=_de_dic_k(L0b[i],0,tot0); i+=1
    uap,_=_de_dic_k(L0b[i],0,tot0); i+=1
    def rd_vint(b,k):
        pp=0;vs=[]
        for _ in range(k): v,pp=_vr(b,pp); vs.append(v)
        return vs
    _ib=L0b[i]; _pl=len(_ib)//3; _p0=_ib[:_pl];_p1=_ib[_pl:2*_pl];_p2=_ib[2*_pl:]
    idc=[_p0[x]|(_p1[x]<<8)|(_p2[x]<<16) for x in range(tot0)]; i+=1
    ms=rd_vint(L0b[i],tot0); i+=1
    j=1
    l1ip=[list(L1b[j+c]) for c in range(4)]; j+=4
    mb=L1b[j]; mp=0; metric=[]
    for _ in range(tot1):
        v,mp=_vr(mb,mp); metric.append(vocab[v])
    j+=1
    vab=L1b[j]; va=[int.from_bytes(vab[3*x:3*x+3],'little') for x in range(tot1)]; j+=1
    flag,_=_de_dic_k(L1b[j],0,tot1); j+=1
    out=[]; l0i=0;l1i=0;c0=0;c1=0
    for pr in parsed:
        if pr[0]==0:
            fmt,n,exc,tl,nrec=pr; ts=l0ts[l0i]; l0i+=1; rows=[]
            for r in range(nrec):
                idx=c0+r
                rows.append('%d %d.%d.%d.%d "%s %s?id=%d" %s %s %dms "%s/%s (%s)"'%(
                    ts[r],ip0[0][idx],ip0[1][idx],ip0[2][idx],ip0[3][idx],
                    method[idx],path[idx],idc[idx],status[idx],size[idx],ms[idx],uan[idx],uav[idx],uap[idx]))
            c0+=nrec; res=[]; rr=0
            for ii in range(n):
                if ii in exc: res.append(exc[ii])
                else: res.append(rows[rr]); rr+=1
            out.append(_lfinish(n,exc,res,tl))
        elif pr[0]==1:
            fmt,n,exc,tl,nrec=pr; ts=l1ts[l1i]; l1i+=1; rows=[]
            for r in range(nrec):
                idx=c1+r
                rows.append('%d,%d.%d.%d.%d,%s,%d.%03d,%s'%(
                    ts[r],l1ip[0][idx],l1ip[1][idx],l1ip[2][idx],l1ip[3][idx],
                    metric[idx],va[idx]//1000,va[idx]%1000,flag[idx]))
            c1+=nrec; res=[]; rr=0
            for ii in range(n):
                if ii in exc: res.append(exc[ii])
                else: res.append(rows[rr]); rr+=1
            out.append(_lfinish(n,exc,res,tl))
        else:
            out.append(codec_logs2_unpack_ref(pr[1],vocab))
    return out
def codec_logs2_unpack_ref(md,vocab):
    return logs2_unpack(md,vocab)
def logs_try_pack(base):
    """Return (fmt, packed_bytes) if a LOGS field-pack round-trips and shrinks, else None."""
    for fmt in (0,1):
        try:
            md=_LOGS_PACK[fmt](base.decode('latin1'))
        except Exception: md=None
        if md is None: continue
        try:
            if _LOGS_UNPACK[fmt](md).encode('latin1')==base: return fmt,md
        except Exception: pass
    return None

def compress(inpath,outpath):
    raw=open(inpath,'rb').read()
    try:
        _compress_structured(raw,outpath)
    except Exception as e:
        sys.stderr.write(f"structured failed ({e}); raw fallback\n")
        blob=b'B256\x00'+lzma.compress(raw,preset=9|lzma.PRESET_EXTREME)
        open(outpath,'wb').write(blob)

import bz2 as _bz2
def _lz(b,lc,pb): return lzma.compress(b,format=lzma.FORMAT_XZ,filters=[{'id':lzma.FILTER_LZMA2,'preset':9|lzma.PRESET_EXTREME,'lc':lc,'lp':0,'pb':pb}])
def _rc_build_freq(data):
    hist=[0]*256
    for b in data: hist[b]+=1
    total=len(data); TOT=1<<16; freq=[0]*256
    if total==0: return freq,0
    nz=[i for i in range(256) if hist[i]]
    for i in nz:
        f=hist[i]*TOT//total
        if f==0: f=1
        freq[i]=f
    s=sum(freq); diff=TOT-s
    mx=max(nz,key=lambda i:freq[i]); freq[mx]+=diff
    if freq[mx]<=0: raise ValueError("scale fail")
    return freq,TOT
def _rc_encode(data):
    freq,TOT=_rc_build_freq(data)
    if TOT==0: return b'',freq
    cum=[0]*257
    for i in range(256): cum[i+1]=cum[i]+freq[i]
    low=0; rng=0xFFFFFFFF; out=bytearray(); MASK=0xFFFFFFFF; TOP=1<<24; BOT=1<<16
    for b in data:
        rng//=TOT; low=(low+cum[b]*rng)&MASK; rng*=freq[b]
        while (low^(low+rng))<TOP or (rng<BOT and ((rng:=(-low)&(BOT-1)) or True)):
            out.append((low>>24)&0xFF); low=(low<<8)&MASK; rng=(rng<<8)&MASK
    for _ in range(4):
        out.append((low>>24)&0xFF); low=(low<<8)&MASK
    return bytes(out),freq
def _rc_decode(enc,freq,n):
    TOT=sum(freq); cum=[0]*257
    for i in range(256): cum[i+1]=cum[i]+freq[i]
    low=0; rng=0xFFFFFFFF; code=0; MASK=0xFFFFFFFF; TOP=1<<24; BOT=1<<16; pos=0
    for _ in range(4):
        code=((code<<8)|(enc[pos] if pos<len(enc) else 0))&MASK; pos+=1
    out=bytearray()
    for _ in range(n):
        rng//=TOT; val=((code-low)&MASK)//rng
        if val>=TOT: val=TOT-1
        lo,hi=0,256
        while lo+1<hi:
            mid=(lo+hi)//2
            if cum[mid]<=val: lo=mid
            else: hi=mid
        b=lo; out.append(b)
        low=(low+cum[b]*rng)&MASK; rng*=freq[b]
        while (low^(low+rng))<TOP or (rng<BOT and ((rng:=(-low)&(BOT-1)) or True)):
            code=((code<<8)|(enc[pos] if pos<len(enc) else 0))&MASK; pos+=1
            low=(low<<8)&MASK; rng=(rng<<8)&MASK
    return bytes(out)
def _rc_pack(b):
    enc,freq=_rc_encode(b)
    hdr=bytearray(); _vi(len(b),hdr)
    nz=[i for i in range(256) if freq[i]]
    hdr.append(len(nz)&0xFF)  # 0 means 256
    for i in nz:
        hdr.append(i); _vi(freq[i],hdr)
    return bytes(hdr)+enc
def _rc_unpack(blob):
    n,p=_vr(blob,0); cnt=blob[p]; p+=1
    if cnt==0: cnt=256
    freq=[0]*256
    for _ in range(cnt):
        sym=blob[p]; p+=1; f,p=_vr(blob,p); freq[sym]=f
    return _rc_decode(blob[p:],freq,n)
def _pack_best(b):
    pr=9 if len(b)>4000000 else 9|lzma.PRESET_EXTREME
    cands=[(0,lzma.compress(b,preset=pr)),(1,lzma.compress(b,format=lzma.FORMAT_XZ,filters=[{'id':lzma.FILTER_LZMA2,'preset':pr,'lc':0,'lp':0,'pb':0}]))]
    if len(b)<=800000:  # extra variants only on small groups (time budget)
        cands.append((2,_lz(b,1,0))); cands.append((3,_bz2.compress(b,9)))
    try:
        cands.append((4,_rc_pack(b)))
    except Exception:
        pass
    cid,blob=min(cands,key=lambda x:len(x[1])); return cid,blob
def _unpack(cid,blob):
    if cid==0: return lzma.decompress(blob)
    if cid==3: return _bz2.decompress(blob)
    if cid==4: return _rc_unpack(blob)
    return lzma.decompress(blob)

def _compress_structured(raw,outpath):
    import base64
    bindata=base64.b64decode(raw)
    hdr,chunks,end=parse(bindata)
    assert end==len(bindata), (end,len(bindata))
    # guard: verify re-encode of parsed structure equals input exactly
    if base64.b64encode(bindata)!=raw:
        raise ValueError("base64 not canonical")
    import hashlib
    gkeys=recover_group_keys(chunks)
    keylist=list(gkeys.values()); keyindex={id(v):i for i,v in enumerate(keylist)}
    # pass 1: per-chunk plain, keyidx, model
    recs=[]  # (keyidx, mid, param, plain)
    for (typ,e1,e2,length,payload,crc) in chunks:
        key=gkeys.get((typ,e2,length)) if (e2&7)==1 else None
        if key is not None:
            plain=km_unmask(payload,key); keyidx=keyindex[id(key)]
            mid,param=try_model(typ,e1,0,length,plain)
        else:
            keyidx=0xFF
            plain=payload if (e2&7)==1 else detransform(payload,e2)
            mid,param=try_model(typ,e1,e2,length,payload)
        recs.append([keyidx,mid,param,plain,None])  # +dref
    # IMG families: chunks in an e1-group sharing top-7 bits -> store base(mem0) + members' LSB planes
    import collections as _cf
    fam_lsb={}
    ig=_cf.defaultdict(list)
    for i,c in enumerate(chunks):
        if c[0]==b'IMG ' and recs[i][1]==0 and recs[i][3] is not None: ig[c[1]].append(i)
    for e1,mem in ig.items():
        mem=sorted(mem)
        if len(mem)<3: continue
        nk=[i for i in mem if recs[i][0]==0xFF]  # reliable (non-kind1) plains
        if not nk: continue
        ref=nk[0]; base=recs[ref][3].translate(_CLR_LSB); n=len(base)
        bi=int.from_bytes(base,'big'); Lref_i=int.from_bytes(recs[ref][3].translate(_SET_LSB),'big')
        good=[]
        for i in mem:
            if len(recs[i][3])!=n: continue
            if recs[i][0]==0xFF:  # non-kind1: reliable LSB
                if recs[i][3].translate(_CLR_LSB)==base: good.append(i)
                continue
            if (chunks[i][2]&7)!=1: continue
            # kind1: recover 7 high bits from base (must be period-251); choose LSB modally vs reference
            ct=chunks[i][4]
            D=(int.from_bytes(ct.translate(_CLR_LSB),'big')^bi).to_bytes(n,'big'); Kh=D[:QKEY]
            if not all(D[r::QKEY]==Kh[r:r+1]*len(D[r::QKEY]) for r in range(QKEY)): continue
            XL=(int.from_bytes(ct.translate(_SET_LSB),'big')^Lref_i).to_bytes(n,'big')
            key=bytes(Kh[r]|(1 if 2*sum(XL[r::QKEY])>len(XL[r::QKEY]) else 0) for r in range(QKEY))
            pl=km_unmask(ct,key)
            if pl.translate(_CLR_LSB)==base:
                keylist.append(key); recs[i][0]=len(keylist)-1; recs[i][3]=pl; good.append(i)
        if len(good)<3: continue
        m0=min(good)  # carrier (smallest index, decoded first) stays mid=0 as a full image
        for i in good:
            if i==m0: continue
            recs[i][1]=17; recs[i][2]=struct.pack('>H',m0); fam_lsb[i]=_pack_lsb(recs[i][3])
    # pass 2: exact cross-chunk references (op 0 copy,1 rev,2 ramp,3 xor5A); source may be longer (prefix)
    hidx={}; pref64={}
    for j,r in enumerate(recs):
        if r[3] is not None:
            hidx.setdefault(hashlib.sha1(r[3]).digest(),j)
            pref64.setdefault(bytes(r[3][:64]),[]).append(j)
    for i,r in enumerate(recs):
        keyidx,mid,param,p,_=r
        if mid!=0 or p is None: continue
        n=len(p); done=False
        for op in range(4):
            if op==0: s=p
            elif op==1: s=p[::-1]
            elif op==2: s=bytes((p[k]-k)&255 for k in range(n))
            else: s=bytes(b^0x5A for b in p)
            # exact same-length
            j=hidx.get(hashlib.sha1(s).digest())
            if j is not None and j<i and len(recs[j][3])==n:
                recs[i][1]=13; recs[i][2]=struct.pack('>H',j)+bytes([op]); done=True; break
            # prefix of a longer source: s == source[:n]
            for j in pref64.get(bytes(s[:64]),()):
                q=recs[j][3]
                if j<i and len(q)>=n and q[:n]==s:
                    recs[i][1]=13; recs[i][2]=struct.pack('>H',j)+bytes([op]); done=True; break
            if done: break
    # pass 2.5: cross-chunk delta references â any earlier chunk (any type/length>=n),
    # op1=xor p^r, op2=sub p-r, op3=rsub r-p; delta stored in residual. Duplicates follow source (j<i).
    SP=1024  # screen prefix
    for i in range(len(recs)):
        if recs[i][1]!=0 or recs[i][3] is None: continue
        p=recs[i][3]; n=len(p); sp=min(SP,n); pi=p[:sp]
        if n<64: continue
        selfc=len(_zlib.compress(pi,1))
        best=None  # (screenc, j, op)
        for j in range(i):
            q=recs[j][3]
            if q is None or len(q)<n: continue
            qi=q[:sp]
            for op in (2,1,3):
                if op==1: d=bytes(pi[k]^qi[k] for k in range(sp))
                elif op==2: d=bytes((pi[k]-qi[k])&255 for k in range(sp))
                else: d=bytes((qi[k]-pi[k])&255 for k in range(sp))
                c=len(_zlib.compress(d,1))
                if best is None or c<best[0]: best=(c,j,op)
        if best and best[0]<selfc*0.6:
            # confirm on full length by actually comparing compressed delta vs self
            j,op=best[1],best[2]; q=recs[j][3]
            step=max(1,n//16384)
            dfull=_dref_apply(p,q,op)
            if len(_zlib.compress(dfull[::step],1))<len(_zlib.compress(p[::step],1))*0.85:
                recs[i][4]=(j,op)
    # serialize
    import collections as _c
    plains=[r[3] for r in recs]
    # build shared word-vocab from LOGS word-text bases (mid==0)
    _wfreq=_c.Counter()
    for i,(typ,e1,e2,length,payload,crc) in enumerate(chunks):
        if typ!=b'LOGS' or recs[i][1]!=0 or recs[i][3] is None: continue
        r=logs_wordtext_ok(recs[i][3].decode('latin1'))
        if not r: continue
        comp,_t=r
        for L in comp: _wfreq.update(L[:-1].split(' '))
    vocab=[w for w,_ in _wfreq.most_common()]
    widx={w:k for k,w in enumerate(vocab)}
    # LOGS columnar pre-pass: gather eligible LOGS chunks (mid0, no dref, known fmt),
    # pack all columns together, verify byte-exact, and mark those chunks mid=18.
    logc_idx=[]
    for i,(typ,e1,e2,length,payload,crc) in enumerate(chunks):
        if typ!=b'LOGS' or recs[i][1]!=0 or recs[i][3] is None or recs[i][4] is not None: continue
        if _logs_classify(recs[i][3].decode('latin1'))<0: continue
        logc_idx.append(i)
    logc_blob=None
    if len(logc_idx)>=2:
        try:
            cand=logs_col_pack([recs[i][3] for i in logc_idx],widx)
            dec=logs_col_unpack(cand,vocab)
            okc=all(dec[k].encode('latin1')==recs[logc_idx[k]][3] for k in range(len(logc_idx)))
        except Exception:
            okc=False
        if okc:
            logc_blob=cand
            for i in logc_idx: recs[i][1]=18
        # else: leave as mid0, fall back to per-chunk pack
    meta=bytearray(); meta+=hdr; meta+=struct.pack('>H',len(chunks))
    meta+=bytes([len(keylist)])
    for k in keylist: meta+=k
    _vi(len(vocab),meta)
    for w in vocab: _vi(len(w),meta); meta+=w.encode('latin1')
    rgroups=_c.OrderedDict(); stats={}
    for idx,((typ,e1,e2,length,payload,crc),(keyidx,mid,param,plain,dref)) in enumerate(zip(chunks,recs)):
        meta+=typ+bytes([e1,e2])+struct.pack('>I',length)+bytes([keyidx,mid])
        if mid==0:
            if dref is not None:
                rj,op=dref; base=_dref_apply(plain,plains[rj],op)
                meta+=bytes([op])+struct.pack('>H',rj)
            else:
                base=plain; meta+=bytes([0])
            pr=None
            if typ==b'LOGS':
                # try word-text (fmt2) using shared vocab, verify round-trip
                w2=logs2_pack(base.decode('latin1'),widx)
                if w2 is not None and logs2_unpack(w2,vocab).encode('latin1')==base:
                    pr=(2,w2)
                if pr is None:
                    pr=logs_try_pack(base)
            if pr is not None and len(_zlib.compress(pr[1],6))<len(_zlib.compress(base,6)):
                fmt,md=pr
                meta+=bytes([254,fmt])+struct.pack('>I',len(md))
                rgroups.setdefault(typ,bytearray()).extend(md)
            else:
                fid,fb=choose_filter(base); meta+=bytes([fid])
                rgroups.setdefault(typ,bytearray()).extend(fb)
        elif mid==18:
            pass  # columnar LOGS: reconstructed from shared LOGC group in chunk order
        else:
            meta+=struct.pack('>H',len(param))+param
            if mid==17: rgroups.setdefault(b'FAML',bytearray()).extend(fam_lsb[idx])
        stats[typ]=stats.get(typ,[0,0]); stats[typ][0]+= (length if mid else 0); stats[typ][1]+=length
    if logc_blob is not None:
        rgroups[b'LOGC']=bytearray(logc_blob)
    meta_c=lzma.compress(bytes(meta),preset=9|lzma.PRESET_EXTREME)
    out=MAGIC+struct.pack('>I',len(meta_c))+meta_c+struct.pack('>H',len(rgroups))
    for typ,buf in rgroups.items():
        cid,blob=_pack_best(bytes(buf))
        out+=typ+bytes([cid])+struct.pack('>I',len(blob))+blob
    open(outpath,'wb').write(out)
    return len(out)

def decompress(inpath,outpath):
    import base64
    d=open(inpath,'rb').read()
    assert d[:4]==b'B256'
    if d[4]==0:  # raw fallback
        open(outpath,'wb').write(lzma.decompress(d[5:])); return
    off=5; mclen=struct.unpack('>I',d[off:off+4])[0]; off+=4
    meta=lzma.decompress(d[off:off+mclen]); off+=mclen
    ngroups=struct.unpack('>H',d[off:off+2])[0]; off+=2
    rbuf={}
    for _ in range(ngroups):
        gtyp=d[off:off+4]; cid=d[off+4]; blen=struct.unpack('>I',d[off+5:off+9])[0]; off+=9
        rbuf[gtyp]=[_unpack(cid,d[off:off+blen]),0]; off+=blen
    hdr=meta[:HDRLEN]; p=HDRLEN
    nch=struct.unpack('>H',meta[p:p+2])[0]; p+=2
    nkeys=meta[p]; p+=1
    keylist=[meta[p+i*QKEY:p+(i+1)*QKEY] for i in range(nkeys)]; p+=nkeys*QKEY
    nvoc,p=_vr(meta,p); vocab=[]
    for _ in range(nvoc):
        L,p=_vr(meta,p); vocab.append(meta[p:p+L].decode('latin1')); p+=L
    out=bytearray(hdr); plains=[]
    _logc={'list':None,'i':0}
    for _ in range(nch):
        typ=meta[p:p+4]; e1=meta[p+4]; e2=meta[p+5]; length=struct.unpack('>I',meta[p+6:p+10])[0]
        keyidx=meta[p+10]; mid=meta[p+11]; p+=12
        key=keylist[keyidx] if keyidx!=0xFF else None
        if mid==18:
            if _logc['list'] is None:
                _logc['list']=logs_col_unpack(rbuf[b'LOGC'][0],vocab)
            plain=_logc['list'][_logc['i']].encode('latin1'); _logc['i']+=1
        elif mid==0:
            op=meta[p]; p+=1
            if op: drj=struct.unpack('>H',meta[p:p+2])[0]; p+=2
            fid=meta[p]; p+=1
            g=rbuf[typ]
            if fid==254:
                fmt=meta[p]; p+=1; mlen=struct.unpack('>I',meta[p:p+4])[0]; p+=4
                md=g[0][g[1]:g[1]+mlen]; g[1]+=mlen
                if fmt==2:
                    base=logs2_unpack(md,vocab).encode('latin1')
                else:
                    base=_LOGS_UNPACK[fmt](md).encode('latin1')
            else:
                fb=g[0][g[1]:g[1]+length]; g[1]+=length
                base=unapply_filter(fb,fid,length)
            plain=_dref_undo(base,plains[drj],op) if op else base
        else:
            plen=struct.unpack('>H',meta[p:p+2])[0]; param=meta[p+2:p+2+plen]; p+=2+plen
            if mid==17:
                m0=struct.unpack('>H',param[:2])[0]; g=rbuf[b'FAML']; pl=(length+7)//8
                packed=g[0][g[1]:g[1]+pl]; g[1]+=pl
                lsb=b''.join(_BITEXP[c] for c in packed)[:length]
                bc=plains[m0].translate(_CLR_LSB)
                plain=(int.from_bytes(bc,'big')|int.from_bytes(lsb,'big')).to_bytes(length,'big')
            elif mid==13:
                j=struct.unpack('>H',param[:2])[0]; op=param[2]; r=plains[j]
                if op==0: plain=r[:length]
                elif op==1: plain=r[:length][::-1]
                elif op==2: plain=bytes((r[k]+k)&255 for k in range(length))
                else: plain=bytes(b^0x5A for b in r[:length])
            else:
                plain=_reconstruct(mid,param,length)
        plains.append(plain)
        if key is not None: payload=km_mask(plain,key)
        elif (e2&7)==1: payload=plain
        else: payload=forward(plain,e2)
        crc=zlib.crc32(typ+bytes([e1,e2])+payload)&0xffffffff
        out+=struct.pack('>I',length)+typ+bytes([e1,e2])+payload+struct.pack('>I',crc)
    binout=bytes(out)
    b64=base64.b64encode(binout)
    open(outpath,'wb').write(b64)

if __name__=='__main__':
    cmd=sys.argv[1]
    if cmd=='--compress': compress(sys.argv[2],sys.argv[3])
    elif cmd=='--decompress': decompress(sys.argv[2],sys.argv[3])
