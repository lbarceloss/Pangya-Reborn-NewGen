# Decryption of the additional Pangya TH layer

This document lets you compare the recovered transformation with your implementation. The Python code below reconstructs behavior equivalent to what was observed; it is not the DLL's original source code.

## Result and sample

The additional routine was located in the **installed ijl15.dll**, RVA **0x4990**. The receive wrapper is at RVA **0x4B20**; the inverse encryption routine is at RVA **0x4940**.

SHA-256 of the analyzed sample:

```text
1C6B9E743C42ECC7D00A192B8606F1EB5BF7D0251F3F8B145193A641704C55C5
```

These addresses identify this sample. New versions should not be assumed to have the same RVAs. In the collected session, the DLL was at base `0x78A60000`, so the decryption routine was at `0x78A64990`. With preferred base `0x10000000`, it corresponds to `0x10004990`.

## How ProjectG understands the data

The observed receive path is:

```text
TCP → packet reassembly and framing
    → ProjectG's original TH decoder
    → LZO decompression
    → ijl15.dll's additional transformation
    → clear opcode and fields interpreted by the client
```

The `ijl15+0x4B20` wrapper first calls the original decoder at `ProjectG:0xA46F40`, connected to routine `0x5AE230`. It then calls `ijl15+0x4990` to undo the additional transformation. This lets the executable continue receiving the expected structure: the DLL adapts it before interpretation.

Changes were observed at receive CALLs `0x492B91` and `0xA45D9A`, redirected to this wrapper. Send CALLs `0x4930A4` and `0xA46174` were redirected to `ijl15+0x49E0`.

In the object used by the wrapper, the buffer pointer is at `+0x04`, the size at `+0x18` and the key at `+0x1C`. The wrapper preserves the first internal control/check byte and transforms only the following bytes. The example below already excludes that byte.

## Additional layer rule

The state starts with the connection's TH key and **resets for each packet**. For each encrypted byte `c`:

```text
p = ROR8(c, 3) XOR state
state = ((state + 0x37 + p) mod 256) XOR 0xA5
```

`ROR8` rotates the byte's eight bits three positions to the right. The update uses the **clear** byte `p`. To encrypt, perform the inverse operation: `c = ROL8(p XOR state, 3)` and use the same state update.

This is the additional layer. It does not replace the outer TH decoder or LZO decompression. The code below does not directly open PCAP/PCAPNG files.

## Complete Python code for comparison

Copy this block into `decrypt_th.py`. It uses only Python's standard library.

```python
import struct


def ror8(value, shift):
    return ((value >> shift) | (value << (8 - shift))) & 0xFF


def rol8(value, shift):
    return ((value << shift) | (value >> (8 - shift))) & 0xFF


def decrypt_inner(ciphertext: bytes, connection_key: int) -> bytes:
    """Accept only the post-TH/LZO payload, without the control byte."""
    if not 0 <= connection_key <= 255:
        raise ValueError("The key must fit in one byte")
    state = connection_key
    plaintext = bytearray()
    for encrypted_byte in ciphertext:
        plain_byte = ror8(encrypted_byte, 3) ^ state
        plaintext.append(plain_byte)
        state = ((state + 0x37 + plain_byte) & 0xFF) ^ 0xA5
    return bytes(plaintext)


def encrypt_inner(plaintext: bytes, connection_key: int) -> bytes:
    if not 0 <= connection_key <= 255:
        raise ValueError("The key must fit in one byte")
    state = connection_key
    ciphertext = bytearray()
    for plain_byte in plaintext:
        ciphertext.append(rol8(plain_byte ^ state, 3))
        state = ((state + 0x37 + plain_byte) & 0xFF) ^ 0xA5
    return bytes(ciphertext)


def parse_wind(packet: bytes) -> dict:
    """Interpret the 0x005B example, without the internal control byte."""
    if len(packet) != 7:
        raise ValueError("Expected a 7-byte wind packet")
    opcode = struct.unpack_from("<H", packet, 0)[0]
    if opcode != 0x005B:
        raise ValueError(f"Unexpected opcode: 0x{opcode:04X}")
    wind_raw = packet[2]
    adjustment_flag = packet[3]
    angle_raw = struct.unpack_from("<H", packet, 4)[0]
    if adjustment_flag != 0:
        raise ValueError("This example validates only a zero adjustment flag")
    return {
        "opcode": f"0x{opcode:04X}",
        "wind_raw": wind_raw,
        "wind_m": wind_raw + 1,
        "adjustment_flag": adjustment_flag,
        "angle_raw": angle_raw,
        "angle_degrees": angle_raw * 360.0 / 255.0,
        "final_flag": packet[6],
    }


if __name__ == "__main__":
    key = 7  # This connection's key, obtained from hello; not universal.
    ciphertext = bytes.fromhex("E2 E1 96 A5 A0 D3 A8")
    expected = bytes.fromhex("5B 00 04 00 5A 00 01")
    plaintext = decrypt_inner(ciphertext, key)
    assert plaintext == expected
    assert encrypt_inner(plaintext, key) == ciphertext
    print("Clear:", plaintext.hex(" ").upper())
    print("Re-encrypted:", encrypt_inner(plaintext, key).hex(" ").upper())
    print("Fields:", parse_wind(plaintext))
```

Run: `python decrypt_th.py`. The result should contain wind **5 m**, raw angle **90** and converted angle **127.05882352941177°**.

## Real example: TH-sessao-C.pcapng

Capture SHA-256: `eb56c15029e86684cf35aaec439b5b195a8398292d8a702b8030dae4547c58d4`.

Wireshark frame **4218**, TCP stream **41**, time **39.8877395 s**, server → client direction. Connection key: **7**.

| Stage | Bytes |
|---|---|
| Complete outer packet | `00 10 00 00 00 00 00 07 18 E2 E1 91 BD 42 32 3E B4 A0 D3` |
| Payload after TH/LZO | `E2 E1 96 A5 A0 D3 A8` |
| Payload after additional layer | `5B 00 04 00 5A 00 01` |

Do not apply `decrypt_inner` directly to the first row: it still contains framing and the outer layer.

| Clear offset | Bytes | Interpretation |
|---|---|---|
| 0–1 | `5B 00` | Opcode `0x005B`, little-endian |
| 2 | `04` | Raw wind 4 → displayed as 5 m in this case |
| 3 | `00` | Negative adjustment flag inactive |
| 4–5 | `5A 00` | Raw angle 90, uint16 little-endian |
| 6 | `01` | Final flag |

The converted angle is `90 × 360 / 255`. It uses the server's reference frame; direction relative to the aim/camera may differ.

### Byte-by-byte comparison

| Offset | Encrypted | ROR8(c,3) | State before | Clear |
|---:|---|---|---|---|
| 0 | E2 | 5C | 07 | 5B |
| 1 | E1 | 3C | 3C | 00 |
| 2 | 96 | D2 | D6 | 04 |
| 3 | A5 | B4 | B4 | 00 |
| 4 | A0 | 14 | 4E | 5A |
| 5 | D3 | 7A | 7A | 00 |
| 6 | A8 | 15 | 14 | 01 |

## Evidence in the copied routine

Excerpts executed during offline emulation of the collected code:

```asm
7913D259  mov al, [edi+edx]
7913D25C  ror al, 3
7913D265  xor al, bl
7913D267  add bl, 37h
78F7F0E4  add bl, al
78F7F0E6  mov [edi+edx], al
78EBD7D2  inc edx
78EBD7D3  xor bl, 0A5h
```

The protected blocks are scattered; these addresses use the loaded base from that collection. The instructions explain the rotation, XOR and state with feedback from the clear byte.

## What was validated and the limits

- The real wrapper was emulated offline with `00 E2 E1 96 A5 A0 D3 A8`, producing `00 5B 00 04 00 5A 00 01`. The first internal byte was preserved. The outer decoder was represented by a successful return in the emulator because the input was already after TH/LZO.
- The actual copied routines passed **224 offline tests**: 112 decryptions and 112 encryptions, keys from 0 to 15 and lengths of 0, 1, 7, 16, 127, 256 and 1024 bytes. They matched the reconstructed formula.
- You had already provided the 5 m value; the angle had not been provided. The known wind confirmed the interpretation, without constituting an independent discovery of that value.
- Re-encrypting the example verifies the inverse operation. A roundtrip alone does not prove that a formula matches the binary; comparison with the copied routines provides the additional evidence.
- The confirmed attribution of this transformation is to **ijl15.dll** from the sample above. This does not claim complete removal of protection, attribution of all routines to ijl15, or an HWID bypass.

To verify the complete path from a capture, the previously delivered reader is in `outputs/Leitor-vento-TH` in the workspace. This document keeps the example short and provides the additional-layer code for the requested comparison.
