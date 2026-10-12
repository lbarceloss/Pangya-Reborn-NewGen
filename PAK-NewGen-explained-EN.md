# Compact Pak: NewGen unpacking explained

Source reviewed: `C:\Users\lbarc\Desktop\Abrir Map Completo\gui`.
Main file: `src/pak.cpp`; SHA-256: `3C96252BB8165E5CC836C87C22A69AD29F6575F227B4DCFE5E8C474FFADB875B`.

This explanation follows the provided source. In this implementation, NewGen uses the same 16-round Pangya XTEA variant as the other profiles, with a different 128-bit key. The key encrypts table metadata and file names. File contents are stored raw or compressed using custom LZ/LZ2; they are not passed through XTEA in `Decompress`.

## Keys side by side

| Profile | Four uint32 key words, in order |
|---|---|
| TH original | `0x050AD33B, 0x00BAFF09, 0x0452FFDA, 0x02CB4422` |
| NewGen | `0xD47B3E91, 0xA82C5F6D, 0x63E1D84A, 0xF5927B1C` |

The source selects the key through `RegionKey("newgen")`. Each word uses little-endian encoding when represented as bytes. There is no IV, salt, password derivation or per-file nonce in this XTEA path.

All four words differ from the original TH key. Source comments describe replacement of the four TH literals at `0xBA4CF2`, and mention an unpacked DLL table offset `0x2246B8`. These are annotations in your source; this task did not independently revalidate those DLL locations.

## Archive layout

All uint32 fields are little-endian. The last nine bytes are the trailer:

| Trailer offset | Size | Field |
|---|---:|---|
| 0 | 4 | File table offset |
| 4 | 4 | Entry count, including directories |
| 8 | 1 | Signature `0x12` |

Each table entry has a 14-byte header followed by the name:

| Header offset | Size | Field |
|---|---:|---|
| 0 | 1 | Stored name length |
| 1 | 1 | Entry type |
| 2 | 4 | Offset, encrypted for XTEA entries |
| 6 | 4 | PackedSize, clear |
| 10 | 4 | RealSize, encrypted for XTEA entries |
| 14 | PathLen | Name bytes |

The offset and realSize are **combined into one eight-byte block**, although their fields are separated by packedSize in the stored header. Read header bytes `[2:6] + [10:14]`, decrypt that block, then restore the first and last four bytes to their fields. Decrypting header bytes `[2:10]` would be wrong.

Names use independent eight-byte blocks (ECB). `XteaDecipher` transforms complete blocks only. The writer zero-pads to a multiple of eight, with a minimum of eight bytes. The reader trims trailing `00` or `CD`, converts EUC-KR/codepage 51949 to UTF-8 and normalizes backslashes to slashes.

## Entry type

| Bits | Meaning |
|---|---|
| Low nibble `0` | Raw file |
| Low nibble `1` | Custom LZ |
| Low nibble `2` | Directory, no content to extract |
| Low nibble `3` | LZ2 with obfuscation |
| High nibble `0x20` | XTEA metadata/name |
| High nibble `0x10` | Legacy XOR |
| High nibble `0x80` | Clear metadata/name |

Thus `0x23` means XTEA table fields/name plus LZ2 content; `0x20` means XTEA table fields/name plus raw content. A zero high nibble is interpreted as legacy XOR. In that branch the name bytes and realSize use XOR `0x71`, and an extra delimiter byte follows the name. The clear-name branch also skips that delimiter; the XTEA branch does not.

## Exact decryption from your C++ source

The helpers `rd32`/`wr32` read/write little-endian uint32. Unsigned arithmetic wraps modulo 2^32. `kRounds = 16` and `kDelta = 0x61C88647`.

```cpp
void XteaDecryptBlock(const uint32_t k[4], uint8_t* buf) {
    uint32_t v0 = rd32(buf), v1 = rd32(buf + 4), sum = 0xE3779B90u;
    for (int i = 0; i < kRounds; i++) {
        v1  -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum >> 11) & 3]);
        sum += kDelta;
        v0  -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
    }
    wr32(buf, v0); wr32(buf + 4, v1);
}
void XteaDecipher(const uint32_t k[4], uint8_t* buf, size_t len) {
    for (size_t o = 0; o + 8 <= len; o += 8) XteaDecryptBlock(k, buf + o);
}
```

Encryption starts with sum zero and subtracts `0x61C88647` each round. Decryption starts with `0xE3779B90` and adds that constant. This is equivalent to adding `0x9E3779B9` during encryption. The round count is important: a generic XTEA implementation with a different count will not match.

## Reproducible Python example

This is a **synthetic metadata block** for comparing the formula, not a claim of a real file at offset `0x12345678`. Clear bytes `78 56 34 12 20 00 00 00` represent offset `0x12345678` and realSize 32. The ciphertext below was generated using the selected profile key. Only the Python standard library is required.

```python
import struct

MASK = 0xFFFFFFFF

def decrypt_block(block: bytes, key) -> bytes:
    if len(block) != 8 or len(key) != 4:
        raise ValueError("Expected 8-byte block and four key words")
    v0, v1 = struct.unpack("<II", block)
    total = 0xE3779B90
    for _ in range(16):
        v1 = (v1 - ((((v0 << 4) ^ (v0 >> 5)) + v0)
                     ^ (total + key[(total >> 11) & 3]))) & MASK
        total = (total + 0x61C88647) & MASK
        v0 = (v0 - ((((v1 << 4) ^ (v1 >> 5)) + v1)
                     ^ (total + key[total & 3]))) & MASK
    return struct.pack("<II", v0, v1)

def decrypt_name(encrypted: bytes, key) -> bytes:
    result = bytearray(encrypted)
    for pos in range(0, len(encrypted) - 7, 8):
        result[pos:pos+8] = decrypt_block(encrypted[pos:pos+8], key)
    return bytes(result).rstrip(b"\x00\xcd")

KEY = (0xD47B3E91, 0xA82C5F6D, 0x63E1D84A, 0xF5927B1C)
ciphertext = bytes.fromhex("47 62 ED 96 32 BD 99 05")
plaintext = decrypt_block(ciphertext, KEY)
assert plaintext == bytes.fromhex("7856341220000000")
offset, real_size = struct.unpack("<II", plaintext)
print(plaintext.hex(" ").upper())
print(f"offset=0x{offset:08X}, realSize={real_size}")
```

Expected output:

```text
78 56 34 12 20 00 00 00
offset=0x12345678, realSize=32
```

## LZ/LZ2 content extraction

`LoadPak` calls `ReadTable`, skips decompression for directories, and calls `Decompress` for each file. This is the provided implementation:

```cpp
std::vector<uint8_t> Decompress(const std::vector<uint8_t>& data, const Entry& e) {
    int ft = e.type & FileTypeMask;
    if (ft == FileTypeBasic) {
        std::vector<uint8_t> raw(e.packedSize);
        if (e.packedSize) std::memcpy(raw.data(), &data[e.offset], e.packedSize);
        return raw;
    }

    std::vector<uint8_t> out;
    out.reserve(e.realSize);
    size_t off = e.offset;
    long long readlen = e.packedSize;
    uint8_t counter = 0, seq = 0, realseq = 0;

    for (long long j = 0; j < readlen;) {
        if (counter == 0) {
            seq = data[off + j];
            realseq = seq;
            j++;
            if (ft == FileTypeLz2) seq ^= 0xC8;
        } else {
            seq >>= 1;
        }

        if ((seq & 1) == 1) {
            uint16_t value = (uint16_t)(data[off + j] | (data[off + j + 1] << 8));
            j += 2;
            if (ft == FileTypeLz2) value ^= kValuePad[(realseq >> 3) & 7];
            int backOff = value & 0xFFF;
            int size    = (value >> 12) + 2;
            int src     = (int)out.size() - backOff;
            for (int k = 0; k < size; k++) out.push_back(out[src + k]);
        } else {
            out.push_back(data[off + j]);
            j++;
        }
        counter = (uint8_t)((counter + 1) & 7);
    }
    return out;
}
```

Each control byte describes up to eight tokens, least significant bit first. Zero means a literal byte; one means a two-byte back-reference. For LZ2, control flags are XORed with `0xC8`. The reference word is XORed with a pad selected by the **original stored control byte**, before that XOR:

```cpp
const uint16_t kValuePad[8] = {
    0xFF21, 0x834F, 0x675F, 0x0034,
    0xF237, 0x815F, 0x4765, 0x0233
};
```

After undoing that obfuscation, `distance = value & 0xFFF` and `length = (value >> 12) + 2`. Copies are byte by byte and may refer to newly appended output bytes. The pad is shared by NewGen and Reborn in this source; it is separate from their XTEA key.

## GUI detection and rebuilding

`main.cpp:TableLooksValid` checks nonempty names, absence of control characters, file offset plus packedSize within the archive and realSize no greater than `0x40000000`. `openPak` tries the selected region first, then the other keys from `RegionList`, and selects the first plausible table. This is structural validation, not cryptographic authentication; archives using only clear/XOR entries may not distinguish XTEA keys.

`BuildPak` sorts paths, derives directories, compresses with LZ2 only if it saves space, writes the data, writes the encrypted table and appends the nine-byte trailer. It emits types `0x22` for directories, `0x23` for compressed files and `0x20` for raw files. Rebuilding may change the archive bytes while preserving file contents.

## Existing CLI usage

These commands illustrate the provided tools; they were not executed in this documentation task. Replace input and output paths before using them. `list` only reads the table; `extracttool` writes extracted files to the destination directory.

```powershell
.\paktool.exe list "C:\path\input.pak" newgen
.\extracttool.exe "C:\path\input.pak" "lobby" "C:\path\extracted" newgen
```

`extracttool` performs a case-insensitive substring match on paths. The selected key applies to each archive; a client directory may contain older archives using the original regional key alongside new archives.

## Verification performed for this document

An independent Python table reader inspected `C:\Users\lbarc\Desktop\Pangya New Gen\projectg884th.pak`. It contains 75 entries; the NewGen key passed the name/range checks, while the original TH key did not. One decoded file entry was `data/lobby00/lobby_spook.gbin`: type `0x23`, offset 891739, packedSize 10613, realSize 27406. Only table metadata was read; the full extraction and client behavior were not tested.

Both profile-specific synthetic examples were executed and recovered the expected eight bytes. This verifies the documented examples; it does not replace a comparison with your original packer or a real archive for every version. No game process was accessed or modified, and no archive was rewritten.

This PAK XTEA variant is separate from the additional packet transformation described in the network document. The source establishes how Compact Pak works; comments about DLL patches are not new runtime evidence.
