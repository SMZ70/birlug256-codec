# birlug256 optimization progress

Target: total < 3,021,554 (beat AFHINORS #1)
Baseline (verified today): OUT=3,265,646, code=13,732, total=3,279,378

## Accepted changes (verified byte-exact round-trip each time)
1. LOGS fmt1 `va` column: decimal-with-3-frac-digits -> int*1000 as fixed 3-byte LE
   (was latin1 dict). OUT 3,265,646 -> 3,221,630 (-44,016). LOGS comp 660,212 -> 616,204.
   compress ~31.7s, decompress ~5.5s. sha match YES.

2. LOGS word-text (3rd format): space-separated made-up words, 488-word shared vocab
   stored once in meta; per-chunk index-varint stream (fmt2). Was plain lzma text.
   OUT 3,221,630 -> 3,137,746 (-83,884). LOGS comp 616,204 -> 530,396.
   compress ~31s, decompress ~5.6s. sha match YES.
   Total ~3,151,478. Need ~130K more to beat 3,021,554.

## FINAL (verified via solution/main.py scorer path)
- OUT=3,137,746  code=14,808  TOTAL=3,152,554
- compress 30.9s, decompress 5.5s (well under 45s local / 60s Alpine budget)
- sha256 round-trip: MATCH (byte-exact), sizes equal
- Target 3,021,554 NOT beaten; gap = 131,000
- Reduction from baseline: 3,279,378 -> 3,152,554 = -126,824

## Why the remaining ~131K resists (measured, not guessed)
- HASH 688K: SHA-256 crypto floor, off-limits (leaders store keys too).
- SEQ2 522K: incompressible chunks have MAXIMAL linear complexity (BM over GF(2)
  = n/2 exactly) -> not LFSR/xorshift/Mersenne; behaves as crypto-PRNG/random. Uncrackable.
- IMG 490K: procedural images; current 1D delta(2048)/laned filters BEAT MED/Paeth/GAP
  2D predictors on the two big carriers (79,220). No win.
- NOIZ 136K & FAML 288K: lzma already AT/BELOW order-0 and order-1 entropy floors.
- LOGS 530K: va(fixed3), ts(zz-delta), IP octets(random), word-vocab all near floors now.
- DUP: only 15^238 pair links (~21K) but prefix-screen misses it; full O(n^2) scan not
  worth the risk/time for one pair.

## Residual map (post-change, biggest levers)
- HASH ~688K — crypto floor, skip
- LOGS ~616K — more column work possible (me dict, fmt0 path/id/ua)
- SEQ2 ~522K — generator cracking
- IMG ~490K — 2D predictors
- FAML 288K, DUP 174K, NOIZ 136K, WAVE 120K, SPRS 101K, RAND 65K

## Session 2026-09-19 (continued) — verified changes
Baseline this session: OUT=3,137,746 code=14,808 total=3,152,554 (re-measured, matches).
3. LOGS columnar repack: all 51 LOGS chunks (17 L0/access, 17 L1/csv, 17 word) packed
   into one shared per-column stream group (LOGC) instead of per-chunk concat.
   ts delta-of-1000 for L1, zz-delta for L0; shared dicts per column.
   OUT 3,137,746 -> 3,114,278 (-23,468). LOGS residual 530,396 -> 507,044. sha YES.
4. metric column = vocab-index varint (all 473 metrics are word-vocab words), drop
   redundant embedded dict; raised _pack_best variant cap 700k->800k so LOGC gets
   pb0/lc1 + bz2 candidates (picked cid=2).
   OUT 3,114,278 -> 3,112,486 (-1,792). LOGC 505,252. sha YES.
   compress ~31s, decompress 5.5s.
Running total: OUT=3,112,486 + code -> ~3,127,294. Target 3,021,554 (need ~106K more).
NOIZ verified NOT crackable: order0==order1 entropy (IID noise), lzma already ~2K above
  the order-0 floor. No seed generator. Skip.

5. Static order-0 range coder as cid=4 in _pack_best/_unpack (32-bit Subbotin, 16-bit
   total, freq table serialized as varint nonzero entries). Selected only when it beats
   lzma/bz2 candidates. FAML: 288,680 -> 268,336 (cid=4). SPRS: ~101K -> 86,530 (cid=4).
   NOIZ/WAVE tried RC and kept lzma cid=1 (structured). OUT 3,112,486 -> 3,076,916
   (-35,570). sha match YES, cmp byte-identical. compress ~34s, decompress ~7-8s.
   Code grew 14,808 -> 17,180 (+2,372 for RC funcs). Net score improvement -33,198.

## FINAL (verified via solution/main.py scorer path, byte-exact)
- OUT=3,076,916  code=17,180  TOTAL=3,094,096
- compress 34.1s, decompress 7.3s (under budget)
- sha256 round-trip MATCH, cmp byte-identical
- Target 3,021,554 NOT beaten; gap = 72,542
- Reduction from session start (3,152,554): -58,458

## Levers examined and rejected this session (measured in-context)
- IMG filter re-rank (full-buffer top-5 confirm in choose_filter): IMG comp moved
  490,532 -> 490,528 only (net worse OUT via other paths). Carrier stays mid=0 in the
  shared IMG residual group; cross-chunk matching already captures its structure, so the
  isolated ~20.6K "idx68 delta(1)" gain does not materialize through the group lzma.
  Reverted.
- HASH (crypto floor), SEQ2 (maximal linear complexity), NOIZ (IID), DUP/RAND (random
  residuals): no productive lever, consistent with prior passes.

## Session 2026-09-19 (agent continuation) — VERIFIED
Baseline confirmed via solution/main.py: OUT=3,076,916 code=17,092 total=3,094,008. Byte-exact, 34.0s/7.1s.

6. choose_filter full-buffer confirm: the old proxy picked the filter by zlib-1 on a 24KB
   PREFIX only. For buffers >=256KB, now rank top-4 zlib-prefix candidates and confirm
   the winner with a real lzma preset-4 measure on the FULL buffer. Fixes IMG carrier
   idx68 (proxy picked laned4; lzma prefers a different filter) and idx54.
   IMG group 490,532 -> 466,920 (-23,612). OUT 3,076,916 -> 3,053,304. sha match YES.
   compress 39.0s / decompress 7.7s. p code +24 bytes only.
   TOTAL 3,094,008 -> 3,070,524. Gap to #1 (3,017,776): 52,748.

7. Lowered choose_filter full-buffer-confirm threshold 262144 -> 100000, top-4 -> top-5.
   This re-picked filters for sub-256KB chunks. Gain landed in DUP (174,156 -> 169,468),
   NOT SEQ2. OUT 3,053,304 -> 3,048,614 (-4,690). sha YES. compress 40.3s / decompress 7.3s.
   TOTAL 3,070,524 -> 3,065,834. Gap to #1: 48,058.
   NOTE: SEQ2 group stayed 522,220 exactly. Per-chunk stride4 gains (idx113/116/181 -> ~2.4K
   standalone) do NOT materialize through the grouped lzma; splitting SEQ2 into
   structured/random subgroups measured WORSE (695K vs 692K standalone). SEQ2 confirmed
   at floor via the real cross-chunk pipeline. Not pursuing further.

8. LOGC L0 'id' column: was varint; ids are ~20-bit uniform (max ~1048411, 4th byte 0).
   Re-encoded as 3-byte LE with byte-plane split (stride 3) -> MSB plane near-constant.
   Verified inside real LOGC blob: 505,252 -> 502,380 standalone; end-to-end OUT
   3,048,614 -> 3,045,742 (-2,872). p code +140. sha YES. 40.1s / 7.2s.
   TOTAL 3,065,834 -> 3,063,102. Gap to #1: 45,326.
   Investigated & confirmed FLOOR: L1 va (a in [0,16383]=2^14 + frac uniform 0-999,
   ~24 bits/val, current 75,536 == entropy floor; splitting worse). ip octets random.
   MED/Paeth 2D predictors far WORSE than current 1D filters on all 4 IMG carriers
   (procedural images, not natural). LOGC blob already optimally packed (lc1pb0).

## FINAL (agent session 2026-09-19) — VERIFIED byte-exact via solution/main.py
- OUT=3,045,742  code=17,360 (p 17,256 + main 104)  TOTAL=3,063,102
- compress 39.8s (Alpine est ~52s, under 60s hard limit) / decompress 7.4s
- sha256 round-trip: MATCH (byte-exact)
- Reduction this session: 3,094,008 -> 3,063,102 = -30,906
- Gap to live #1 (mortezam037 3,017,776): 45,326 (NOT beaten)
- Wins: choose_filter full-buffer lzma confirm (IMG -23,612; DUP -4,690 via lowered
  threshold) + LOGC id byte-plane split (-2,872).
- Remaining groups are measured floors: HASH/RAND (crypto/random), SEQ2 (maximal linear
  complexity; per-chunk filter gains wash out in the grouped lzma, split subgroups worse),
  NOIZ (IID), WAVE (lane filter optimal, 16-bit delta worse), FAML (near-random LSB planes,
  XOR-ref worse), SPRS (RC-coded sparse), LOGC va/ip/ms columns (at entropy floor).
  MED/Paeth 2D predictors far worse than 1D filters on procedural IMG carriers.
- Group sizes: HASH 688,224 | SEQ2 522,220 | LOGC 502,380 | IMG 466,920 | FAML 268,336 |
  DUP 169,468 | NOIZ 136,188 | WAVE 120,192 | SPRS 86,524 | RAND 65,608 | meta 18,608.
