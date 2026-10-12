# Decifragem da camada adicional do Pangya TH

Este documento permite comparar a transformação recuperada com sua implementação. O código Python abaixo é uma reconstrução equivalente do comportamento observado, não o código-fonte original da DLL.

## Resultado e amostra

A rotina adicional foi localizada na **ijl15.dll instalada**, RVA **0x4990**. O wrapper de recepção está no RVA **0x4B20**; a rotina inversa, de cifragem, no RVA **0x4940**.

SHA-256 da amostra analisada:

```text
1C6B9E743C42ECC7D00A192B8606F1EB5BF7D0251F3F8B145193A641704C55C5
```

Esses endereços identificam essa amostra. Não se deve assumir que versões novas tenham os mesmos RVAs. Na sessão coletada, a DLL estava na base `0x78A60000`, portanto a rotina de decifragem estava em `0x78A64990`. Com base preferida `0x10000000`, corresponde a `0x10004990`.

## Como o ProjectG entende os dados

O caminho de recepção observado é:

```text
TCP → remontagem e enquadramento dos packets
    → decoder TH antigo do ProjectG
    → descompressão LZO
    → transformação adicional da ijl15.dll
    → opcode e campos claros que o cliente interpreta
```

O wrapper `ijl15+0x4B20` chama primeiro o decoder original em `ProjectG:0xA46F40`, ligado à rotina `0x5AE230`. Depois chama `ijl15+0x4990` para desfazer a transformação adicional. Assim, o executável continua recebendo a estrutura esperada: a DLL faz a adaptação antes da interpretação.

Foram observadas mudanças nos CALLs de recepção em `0x492B91` e `0xA45D9A`, redirecionados para esse wrapper. Os CALLs de envio `0x4930A4` e `0xA46174` foram redirecionados para `ijl15+0x49E0`.

No objeto usado pelo wrapper, o ponteiro do buffer fica em `+0x04`, o tamanho em `+0x18` e a chave em `+0x1C`. O wrapper preserva o primeiro byte interno de controle/verificação e transforma somente os bytes seguintes. O exemplo abaixo já exclui esse byte.

## Regra da camada adicional

O estado começa com a chave TH da conexão e **reinicia a cada packet**. Para cada byte cifrado `c`:

```text
p = ROR8(c, 3) XOR estado
estado = ((estado + 0x37 + p) mod 256) XOR 0xA5
```

`ROR8` gira os oito bits do byte três posições para a direita. A atualização usa o byte **claro** `p`. Para cifrar, faça a operação inversa: `c = ROL8(p XOR estado, 3)` e use a mesma atualização do estado.

Essa é a camada adicional. Ela não substitui o decoder TH externo nem a descompressão LZO. O código abaixo não abre diretamente arquivos PCAP/PCAPNG.

## Código Python completo para comparar

Copie este bloco para `decrypt_th.py`. Usa somente a biblioteca padrão do Python.

```python
import struct


def ror8(value, shift):
    return ((value >> shift) | (value << (8 - shift))) & 0xFF


def rol8(value, shift):
    return ((value << shift) | (value >> (8 - shift))) & 0xFF


def decrypt_inner(ciphertext: bytes, connection_key: int) -> bytes:
    """Recebe somente o payload depois de TH/LZO, sem byte de controle."""
    if not 0 <= connection_key <= 255:
        raise ValueError("A chave deve caber em um byte")
    state = connection_key
    plaintext = bytearray()
    for encrypted_byte in ciphertext:
        plain_byte = ror8(encrypted_byte, 3) ^ state
        plaintext.append(plain_byte)
        state = ((state + 0x37 + plain_byte) & 0xFF) ^ 0xA5
    return bytes(plaintext)


def encrypt_inner(plaintext: bytes, connection_key: int) -> bytes:
    if not 0 <= connection_key <= 255:
        raise ValueError("A chave deve caber em um byte")
    state = connection_key
    ciphertext = bytearray()
    for plain_byte in plaintext:
        ciphertext.append(rol8(plain_byte ^ state, 3))
        state = ((state + 0x37 + plain_byte) & 0xFF) ^ 0xA5
    return bytes(ciphertext)


def parse_wind(packet: bytes) -> dict:
    """Interpreta o exemplo 0x005B, sem byte de controle interno."""
    if len(packet) != 7:
        raise ValueError("Esperado packet de vento com 7 bytes")
    opcode = struct.unpack_from("<H", packet, 0)[0]
    if opcode != 0x005B:
        raise ValueError(f"Opcode inesperado: 0x{opcode:04X}")
    wind_raw = packet[2]
    adjustment_flag = packet[3]
    angle_raw = struct.unpack_from("<H", packet, 4)[0]
    if adjustment_flag != 0:
        raise ValueError("Este exemplo valida somente flag de ajuste zero")
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
    key = 7  # Chave desta conexão, obtida do hello; não é universal.
    ciphertext = bytes.fromhex("E2 E1 96 A5 A0 D3 A8")
    expected = bytes.fromhex("5B 00 04 00 5A 00 01")
    plaintext = decrypt_inner(ciphertext, key)
    assert plaintext == expected
    assert encrypt_inner(plaintext, key) == ciphertext
    print("Claro:", plaintext.hex(" ").upper())
    print("Recifrado:", encrypt_inner(plaintext, key).hex(" ").upper())
    print("Campos:", parse_wind(plaintext))
```

Execute: `python decrypt_th.py`. O resultado deve conter vento **5 m**, ângulo bruto **90** e ângulo convertido **127,05882352941177°**.

## Exemplo real: TH-sessao-C.pcapng

Captura SHA-256: `eb56c15029e86684cf35aaec439b5b195a8398292d8a702b8030dae4547c58d4`.

Frame Wireshark **4218**, stream TCP **41**, instante **39,8877395 s**, direção servidor → cliente. Chave da conexão: **7**.

| Etapa | Bytes |
|---|---|
| Packet externo completo | `00 10 00 00 00 00 00 07 18 E2 E1 91 BD 42 32 3E B4 A0 D3` |
| Payload após TH/LZO | `E2 E1 96 A5 A0 D3 A8` |
| Payload após camada adicional | `5B 00 04 00 5A 00 01` |

Não aplique `decrypt_inner` diretamente à primeira linha: ela ainda contém o enquadramento e a camada externa.

| Offset claro | Bytes | Interpretação |
|---|---|---|
| 0–1 | `5B 00` | Opcode `0x005B`, little-endian |
| 2 | `04` | Vento bruto 4 → exibido como 5 m, neste caso |
| 3 | `00` | Flag de ajuste negativo inativo |
| 4–5 | `5A 00` | Ângulo bruto 90, uint16 little-endian |
| 6 | `01` | Flag final |

O ângulo convertido é `90 × 360 / 255`. É o referencial do servidor; a direção relativa à mira/câmera pode ser diferente.

### Comparação byte a byte

| Offset | Cifrado | ROR8(c,3) | Estado antes | Claro |
|---:|---|---|---|---|
| 0 | E2 | 5C | 07 | 5B |
| 1 | E1 | 3C | 3C | 00 |
| 2 | 96 | D2 | D6 | 04 |
| 3 | A5 | B4 | B4 | 00 |
| 4 | A0 | 14 | 4E | 5A |
| 5 | D3 | 7A | 7A | 00 |
| 6 | A8 | 15 | 14 | 01 |

## Evidência na rotina copiada

Trechos executados na emulação offline do código coletado:

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

Os blocos protegidos estão espalhados; esses endereços são da base carregada naquela coleta. As instruções explicam a rotação, o XOR e o estado com realimentação pelo byte claro.

## O que foi validado e quais são os limites

- O wrapper real foi emulado offline com `00 E2 E1 96 A5 A0 D3 A8`, produzindo `00 5B 00 04 00 5A 00 01`. O primeiro byte interno foi preservado. O decoder externo foi representado por um retorno de sucesso no emulador, pois a entrada já estava após TH/LZO.
- As rotinas reais copiadas passaram em **224 testes offline**: 112 decifragens e 112 cifragens, chaves de 0 a 15 e tamanhos 0, 1, 7, 16, 127, 256 e 1024 bytes. Coincidiram com a fórmula reconstruída.
- O valor 5 m havia sido informado por você; o ângulo não. O vento conhecido confirmou a interpretação, sem constituir descoberta independente desse valor.
- O teste de recifragem do exemplo verifica a operação inversa. Isoladamente, um roundtrip não prova que uma fórmula corresponde ao binário; a comparação com as rotinas copiadas é a evidência adicional.
- A atribuição confirmada desta transformação é à **ijl15.dll** da amostra acima. Isso não afirma remoção completa das proteções, atribuição de todas as rotinas à ijl15, nem bypass de HWID.

Para conferir o caminho completo a partir de captura, o leitor já entregue está em `outputs/Leitor-vento-TH` no workspace. Este documento mantém o exemplo curto e o código da camada adicional para a comparação solicitada.
