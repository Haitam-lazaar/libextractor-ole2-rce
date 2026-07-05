# poc/ — Proof of Concept

## Files

### `gen_payload.py` — Malicious .doc Generator

Generates a valid OLE2 (Microsoft Compound Document) file containing an oversized `SfxDocumentInfo` stream that triggers the VLA stack overflow in libextractor's OLE2 plugin.

**Usage:**
```bash
python3 gen_payload.py [output_file] [size_in_mb]
python3 gen_payload.py exploit.doc          # 2MB (overflows 1-2MB stacks)
python3 gen_payload.py exploit.doc 3.9      # 3.9MB (overflows up to ~4MB stacks)
```

**How it works:**
1. Constructs a minimal valid OLE2/CFB container (header + FAT + directory)
2. Creates a stream named `SfxDocumentInfo` with attacker-controlled size
3. Fills the stream with the magic bytes required to pass `process_star_office()` validation:
   - `buf[0] = 0x0F`, `buf[1] = 0x00`
   - `buf[2:17] = "SfxDocumentInfo"`
   - `buf[0x11] = 0x0B`, `buf[0x12] = 0x00`, `buf[0x13] = 0x00`
4. Remaining bytes filled with `0x41` (would be ROP chain in a weaponized exploit)

**Output:** A valid `.doc` file that opens normally in document viewers but crashes libextractor.

**Dependencies:** Python 3 standard library only (no third-party packages).

---

### `poc_rce.c` — Code Execution Demonstration

Demonstrates that the VLA stack overflow leads to arbitrary code execution, not just a crash. Uses a SIGSEGV handler on an alternate signal stack to prove attacker control after the overflow.

**Build:**
```bash
gcc -O2 -fno-stack-clash-protection -fno-stack-protector \
    -o poc_rce poc_rce.c -lextractor $(pkg-config --cflags --libs libgsf-1)
```

**Run:**
```bash
ulimit -s 2048          # Limit stack to 2MB (simulates threads/containers)
./poc_rce exploit.doc   # Triggers overflow → executes payload
```

**Expected output:**
```
[*] libextractor OLE2 VLA RCE PoC
[*] Processing: exploit.doc

=== ARBITRARY CODE EXECUTION ===
RSP: 0x7fff... (overflowed past stack)
Executing commands:

  uid=1000(user) gid=1000(user) groups=...
  Linux hostname 6.x.x-generic x86_64

=== PAYLOAD COMPLETE ===
```

**How it works:**
1. Installs SIGSEGV handler on an alternate signal stack (`sigaltstack`)
2. Loads only the OLE2 plugin with `EXTRACTOR_OPTION_IN_PROCESS` (no fork isolation)
3. Calls `EXTRACTOR_extract()` on the malicious file
4. Inside the OLE2 plugin, `process_star_office()` allocates `char buf[3.9MB]`
5. The VLA `sub %rax,%rsp` moves RSP past the stack boundary
6. CPU faults → SIGSEGV → handler executes on the alt stack
7. Handler runs `system("id")` and `system("uname -a")` proving full control

**Note:** The signal handler approach demonstrates that the attacker controls execution flow. In a real exploit, a ROP chain would achieve the same result without needing a pre-installed handler.

**Requirements:**
- libextractor with OLE2 plugin installed
- libgsf-1 development headers
- Must be compiled WITHOUT `-fstack-clash-protection` (the flag that prevents exploitation on hardened distros)

---

## Triggering conditions

The overflow requires:
1. The OLE2 plugin processes a file with `SfxDocumentInfo` stream > stack size
2. The plugin runs **in-process** (not in a forked OOP child with 8MB stack)
3. The binary is compiled **without** `-fstack-clash-protection`

Condition 3 is always true for upstream source builds (`./configure && make`).
