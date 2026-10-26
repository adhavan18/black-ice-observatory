# safe reverse-engineering exercise

this repository uses a tiny synthetic byte fixture to demonstrate the first step of reverse engineering: identify the file format and inspect metadata without executing it.

the analysis module recognizes the `mz` and `elf` magic values, reads the pe header offset when available, computes entropy, and extracts printable strings. it does not disassemble or run the fixture.

for a real approved reversing lab, the next boundary would be an isolated container with radare2 or ghidra, no network access, disposable credentials, and a writeup that records commands and findings. real malware must never be uploaded to this public repository.
