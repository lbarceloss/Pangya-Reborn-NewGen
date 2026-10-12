# Compact Pak: unpack do NewGen explicado

Código-fonte lido: `C:\Users\lbarc\Desktop\Abrir Map Completo\gui`.
Arquivo principal: `src/pak.cpp`; SHA-256: `3C96252BB8165E5CC836C87C22A69AD29F6575F227B4DCFE5E8C474FFADB875B`.

Esta explicação acompanha o código fornecido. Nesta implementação, o NewGen usa a mesma variante XTEA do Pangya de 16 rodadas dos demais perfis, com outra chave de 128 bits. A chave cifra metadados da tabela e nomes de arquivos. Os conteúdos ficam sem compressão ou comprimidos com LZ/LZ2 próprio; não passam por XTEA em `Decompress`.

## Chaves lado a lado

| Perfil | Quatro palavras uint32 da chave, em ordem |
|---|---|
| TH original | `0x050AD33B, 0x00BAFF09, 0x0452FFDA, 0x02CB4422` |
| NewGen | `0xD47B3E91, 0xA82C5F6D, 0x63E1D84A, 0xF5927B1C` |

O código seleciona a chave por `RegionKey("newgen")`. Cada palavra usa little-endian quando representada como bytes. Nesse caminho XTEA não há IV, salt, derivação por senha nem nonce por arquivo.

As quatro palavras diferem da chave TH original. Os comentários descrevem a substituição dos quatro literais TH em `0xBA4CF2` e mencionam o offset de tabela `0x2246B8` de uma DLL desempacotada. São anotações do seu código; esta tarefa não revalidou esses locais da DLL de forma independente.

## Estrutura do arquivo

Todos os campos uint32 usam little-endian. Os últimos nove bytes formam o trailer:

| Offset no trailer | Tamanho | Campo |
|---|---:|---|
| 0 | 4 | Offset da tabela de arquivos |
| 4 | 4 | Quantidade de entradas, incluindo diretórios |
| 8 | 1 | Assinatura `0x12` |

Cada entrada da tabela tem um cabeçalho de 14 bytes seguido pelo nome:

| Offset no cabeçalho | Tamanho | Campo |
|---|---:|---|
| 0 | 1 | Comprimento armazenado do nome |
| 1 | 1 | Tipo da entrada |
| 2 | 4 | Offset, cifrado nas entradas XTEA |
| 6 | 4 | PackedSize, em claro |
| 10 | 4 | RealSize, cifrado nas entradas XTEA |
| 14 | PathLen | Bytes do nome |

Offset e realSize são **reunidos em um único bloco de oito bytes**, apesar de estarem separados por packedSize no cabeçalho armazenado. Leia os bytes `[2:6] + [10:14]`, decifre esse bloco e devolva as primeiras e últimas quatro posições aos campos correspondentes. Decifrar os bytes `[2:10]` do cabeçalho seria errado.

Os nomes usam blocos independentes de oito bytes (ECB). `XteaDecipher` transforma somente blocos completos. O gravador preenche com zeros até múltiplo de oito, com mínimo de oito bytes. O leitor remove `00` ou `CD` finais, converte EUC-KR/codepage 51949 para UTF-8 e normaliza barras invertidas para barras comuns.

## Tipo da entrada

| Bits | Significado |
|---|---|
| Nibble inferior `0` | Arquivo sem compressão |
| Nibble inferior `1` | LZ próprio |
| Nibble inferior `2` | Diretório, sem conteúdo a extrair |
| Nibble inferior `3` | LZ2 com ofuscação |
| Nibble superior `0x20` | Metadados/nome XTEA |
| Nibble superior `0x10` | XOR legado |
| Nibble superior `0x80` | Metadados/nome em claro |

Assim, `0x23` significa campos/nome XTEA mais conteúdo LZ2; `0x20` significa campos/nome XTEA mais conteúdo sem compressão. Nibble superior zero é interpretado como XOR legado. Nesse ramo, os bytes do nome e realSize usam XOR `0x71`, e há um byte delimitador extra após o nome. O ramo de nome em claro também pula esse delimitador; o ramo XTEA não.

## Decifragem exata do seu código C++

Os auxiliares `rd32`/`wr32` leem/gravam uint32 little-endian. A aritmética sem sinal dá a volta módulo 2^32. `kRounds = 16` e `kDelta = 0x61C88647`.

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

A cifragem inicia a soma em zero e subtrai `0x61C88647` a cada rodada. A decifragem inicia em `0xE3779B90` e soma essa constante. Isso equivale a somar `0x9E3779B9` durante a cifragem. A quantidade de rodadas importa: uma implementação genérica de XTEA com outra quantidade não vai coincidir.

## Exemplo Python reproduzível

Este é um **bloco sintético de metadados** para comparar a fórmula, não uma alegação de arquivo real no offset `0x12345678`. Os bytes claros `78 56 34 12 20 00 00 00` representam offset `0x12345678` e realSize 32. O cifrado abaixo foi gerado com a chave do perfil selecionado. Usa somente a biblioteca padrão do Python.

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

Saída esperada:

```text
78 56 34 12 20 00 00 00
offset=0x12345678, realSize=32
```

## Extração do conteúdo LZ/LZ2

`LoadPak` chama `ReadTable`, pula a descompressão de diretórios e chama `Decompress` para cada arquivo. Esta é a implementação fornecida:

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

Cada byte de controle descreve até oito tokens, começando pelo bit menos significativo. Zero significa byte literal; um significa referência de dois bytes a conteúdo anterior. No LZ2, as flags de controle recebem XOR `0xC8`. A palavra da referência recebe XOR com um pad selecionado pelo **byte de controle original armazenado**, antes desse XOR:

```cpp
const uint16_t kValuePad[8] = {
    0xFF21, 0x834F, 0x675F, 0x0034,
    0xF237, 0x815F, 0x4765, 0x0233
};
```

Após desfazer essa ofuscação, `distância = value & 0xFFF` e `comprimento = (value >> 12) + 2`. A cópia acontece byte a byte e pode referenciar bytes recém-adicionados à saída. O pad é compartilhado por NewGen e Reborn nesse código; é separado da chave XTEA de cada perfil.

## Detecção da GUI e reconstrução

`main.cpp:TableLooksValid` verifica nomes não vazios, ausência de caracteres de controle, offset do arquivo mais packedSize dentro do arquivo e realSize no máximo `0x40000000`. `openPak` tenta primeiro a região selecionada, depois as outras chaves de `RegionList`, e escolhe a primeira tabela plausível. É validação estrutural, não autenticação criptográfica; arquivos com entradas somente em claro/XOR podem não distinguir chaves XTEA.

`BuildPak` ordena caminhos, deriva diretórios, comprime com LZ2 somente quando economiza espaço, grava os dados, grava a tabela cifrada e acrescenta o trailer de nove bytes. Emite tipos `0x22` para diretórios, `0x23` para arquivos comprimidos e `0x20` para arquivos sem compressão. A reconstrução pode mudar os bytes do pacote mantendo os conteúdos dos arquivos.

## Uso da CLI existente

Estes comandos ilustram as ferramentas fornecidas; não foram executados nesta tarefa de documentação. Substitua os caminhos de entrada e saída antes de usar. `list` somente lê a tabela; `extracttool` grava arquivos extraídos na pasta de destino.

```powershell
.\paktool.exe list "C:\path\input.pak" newgen
.\extracttool.exe "C:\path\input.pak" "lobby" "C:\path\extracted" newgen
```

`extracttool` procura a substring nos caminhos sem diferenciar maiúsculas de minúsculas. A chave escolhida vale para cada pacote; uma pasta do cliente pode conter pacotes antigos com a chave regional original junto de pacotes novos.

## Verificação realizada para este documento

Um leitor independente de tabela em Python examinou `C:\Users\lbarc\Desktop\Pangya New Gen\projectg884th.pak`. Ele contém 75 entradas; a chave NewGen passou nas verificações de nomes/limites, enquanto a chave TH original não passou. Uma entrada de arquivo decodificada foi `data/lobby00/lobby_spook.gbin`: tipo `0x23`, offset 891739, packedSize 10613, realSize 27406. Foram lidos somente os metadados da tabela; não foram testadas a extração completa nem a execução do cliente.

Os dois exemplos sintéticos específicos dos perfis foram executados e recuperaram os oito bytes esperados. Isso verifica os exemplos documentados; não substitui a comparação com seu packer original ou com um arquivo real de cada versão. Nenhum processo do jogo foi acessado ou modificado, e nenhum pacote foi regravado.

Esta variante XTEA dos PAKs é separada da transformação adicional de packets descrita no documento de rede. O código-fonte estabelece como funciona o Compact Pak; os comentários sobre patches nas DLLs não são nova evidência de execução.
