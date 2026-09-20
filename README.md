# birlug/256 — a personal AI experiment

This folder is my playground for the [birlug/256](https://github.com/birlug/256)
compression challenge. I did it for fun, as an excuse to see how far an AI
assistant could get at a hard, open-ended problem: reverse engineering the
challenge blob, spotting structure, cracking the generators, and squeezing the
size down. It was a great way to poke at the tooling, not a serious competitive
entry.

## Not in the rankings

I do not want to be listed on the official scoreboard. Please do not add me
(handle `smz70`) to `participants.json`, and if I ever show up there, take me
out. Any scores you see in my notes were graded locally on my own machine, just
to track my own progress. This was never meant to go on the public leaderboard.

Huge respect to everyone actually competing. This one is just me having fun with
AI.

## What's here

- `challenge.bin` / `challenge.b64` — the challenge data
- `codec.py` — the working compressor/decompressor
- `solution/` — the packaged entry (loader plus lzma-compressed source)
- everything else — scratch scripts from the exploration: generator cracking,
  key recovery, image filters, log parsing, and a lot of dead ends

## Running it

```
python codec.py compress challenge.bin out.bin
python codec.py decompress out.bin roundtrip.bin
```

Round trip is byte exact. Grading uses the official Docker scorer in
`evaluate.py`.

## Build note

`solution/p` is the minified build of `codec.py` (via python-minifier), lzma-compressed. The scorer only counts the `solution/` folder. Verified byte-exact round trip; local score 3,051,674 (compressed 3,038,842 + code 12,832).
