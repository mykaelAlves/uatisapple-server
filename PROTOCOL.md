# Protocolo Uatisapple (servidor ↔ cliente)

Este documento define o formato de bytes exato que o servidor implementa, com base no
enunciado do Trabalho Prático 3. Os pontos que o enunciado deixa em aberto estão
marcados com **(decisão)**, junto com a justificativa.

Todos os inteiros são **big-endian**. `||` indica concatenação.

## 1. Framing TCP

```
length (4B, uint32) || frame (length bytes)
frame = type (1B) || body
```

| Tipo   | Nome           | Direção           |
|--------|----------------|-------------------|
| `0x01` | `CLIENT_HELLO` | cliente → servidor |
| `0x02` | `SERVER_HELLO` | servidor → cliente |
| `0x10` | `E2E`          | ambos (relay)     |
| `0x20` | `ADMIN`        | servidor → cliente |

**(decisão)** O byte de tipo existe porque frames E2E e mensagens administrativas
trafegam no mesmo stream e o cliente precisa distingui-los. O frame E2E em si
continua exatamente como no enunciado.

Limites:
- Cliente → servidor: `length` entre 1 e **4165** (`1 + 52 + 4096 + 16`). Fora disso
  é **erro de framing fatal**.
- Servidor → cliente: até 65536 bytes (o `PEER_LIST` cresce com o número de clientes).
- Se o prefixo anunciar mais bytes do que os que chegam em 10 s, o servidor trata
  como erro de framing fatal.

## 2. Handshake

### 2.1 `CLIENT_HELLO` (cliente → servidor)

```
0x01 || client_id (16B, UUID v4) || pk_C (32B, X25519 raw)
```

O frame tem exatamente 49 bytes. O cliente tem 10 s para enviá-lo depois de conectar.
Se o hello for inválido (tamanho, UUID que não é v4, chave X25519 de ordem baixa), o
servidor fecha a conexão sem responder.

### 2.2 `SERVER_HELLO` (servidor → cliente)

```
0x02 || pk_S (32B) || salt_srv (16B)
     || sig_len (2B) || signature (sig_len)
     || cert_len (2B) || server.crt (cert_len, DER)
```

- **(decisão)** `pk_S` é uma chave **X25519 efêmera** gerada pelo servidor para cada
  handshake (32 bytes raw). Isso segue o enunciado: "certificado RSA usado para assinar
  a chave efêmera ECDHE". A chave privada correspondente é descartada assim que
  `Key_S2C` é derivada (ver §4).
- `salt_srv`: 16 bytes aleatórios, novos a cada handshake.
- `signature` = RSA-PSS(SHA-256, MGF1-SHA-256, salt length = 32) sobre
  `H = SHA256(pk_S || pk_C || client_id || salt_srv)`.
  - O servidor assina `H` como hash pré-calculado (`Prehashed`). Isso equivale a
    assinar o material concatenado com SHA-256, então o cliente pode verificar de
    qualquer uma destas formas:
    ```python
    pub.verify(sig, pk_S + pk_C + client_id + salt, PSS(MGF1(SHA256()), 32), SHA256())
    pub.verify(sig, H, PSS(MGF1(SHA256()), 32), Prehashed(SHA256()))
    ```
- `server.crt`: certificado RSA autoassinado em DER. O cliente **deve** compará-lo
  byte a byte (ou pelo fingerprint SHA-256) com o certificado pinado e só então usar a
  chave pública dele para verificar `signature`.

O certificado fica em `certs/server.crt` (gerado na primeira execução). O fingerprint
SHA-256 aparece no log quando o servidor sobe.

### 2.3 Registro

Depois do `SERVER_HELLO`, o servidor:
1. rejeita a conexão com `ERROR` + `DISCONNECT` se o `client_id` já tiver uma sessão
   ativa ou se o limite de clientes tiver sido atingido;
2. registra a sessão (`seq_send = 0`, `seq_recv = -1`);
3. envia ao novo cliente `REGISTERED` e depois `PEER_LIST` com todos os clientes ativos;
4. envia `PEER_JOINED` para cada um dos outros clientes.

## 3. Salt E2E por par **(decisão)**

O enunciado diz que `PRK = HKDF-Extract(salt_srv, Z_AB)`, mas cada cliente recebe um
`salt_srv` diferente no próprio handshake. Por isso o servidor gera um **`pair_salt`
aleatório de 16 bytes para cada par (A, B)** no momento em que o par se forma, e envia
o **mesmo** valor aos dois: para B no `PEER_LIST`/`PEER_JOINED` sobre A, e para A no
`PEER_JOINED`/`PEER_LIST` sobre B.

Consequências:
- Toda reconexão gera `pair_salt` novos, então chaves E2E nunca são reutilizadas (RS08).
- O servidor conhece o `pair_salt`, mas não `Z_AB`, então continua sem conseguir
  decifrar nada.
- Como o `pair_salt` chega pelo canal administrativo autenticado (§4), um MITM não
  consegue trocar nem o salt nem a `pk` do par.

Derivação no cliente (sugestão para que os dois lados concordem sobre os papéis):
```
A = par com o menor client_id (comparando os 16 bytes); B = o outro
Z_AB    = X25519(sk_self, pk_peer)
PRK     = HKDF-Extract(pair_salt, Z_AB)
Key_A2B = HKDF-Expand(PRK, "A2B", 16)
Key_B2A = HKDF-Expand(PRK, "B2A", 16)
```

## 4. Mensagens administrativas (`ADMIN`, servidor → cliente)

**(decisão)** Para que as mensagens de controle tenham ordenação e proteção contra
replay e adulteração (RS06), elas são cifradas com uma chave de canal por sessão:

```
Z_CS    = X25519(sk_S_efêmera, pk_C)  = X25519(sk_C, pk_S)
Key_S2C = HKDF-SHA256(salt = salt_srv, IKM = Z_CS, info = "S2C", L = 16)
```

Formato:
```
0x20 || seq_no (8B) || AES-128-GCM(Key_S2C, nonce, plaintext, AAD) (ciphertext || tag 16B)
nonce     = 0x00000001 || seq_no      (direction s2c, conforme o enunciado)
AAD       = 0x20 || seq_no
plaintext = admin_type (1B) || payload
```

`seq_no` é o `seq_send` da sessão: começa em 0 e é incrementado a cada mensagem. O
cliente deve rejeitar `seq_no <= último recebido` (começando em -1) e qualquer falha
na tag GCM.

| `admin_type` | Nome          | Payload |
|--------------|---------------|---------|
| `0x01` | `REGISTERED`  | vazio |
| `0x02` | `PEER_LIST`   | `count (2B) \|\| count × entry` |
| `0x03` | `PEER_JOINED` | `entry` |
| `0x04` | `PEER_LEFT`   | `client_id (16B)` |
| `0x05` | `ERROR`       | `code (1B) \|\| mensagem UTF-8` |
| `0x06` | `DISCONNECT`  | `reason (1B) \|\| mensagem UTF-8` |

`entry = client_id (16B) || pk (32B) || pair_salt (16B)` (64 bytes)

Códigos de `ERROR`:

| Código | Nome | Fatal? |
|--------|------|--------|
| `0x01` | `FRAMING` (tamanho inválido, frame truncado/incompleto, frame E2E fora dos limites) | sim |
| `0x02` | `INVALID_MESSAGE` (tipo inesperado após o handshake) | sim |
| `0x03` | `UNKNOWN_RECIPIENT` (destinatário não conectado, ou o próprio remetente) | não |
| `0x04` | `SENDER_MISMATCH` (`sender_id` diferente do `client_id` da sessão) | não |
| `0x05` | `REPLAY` (`seq_no` não é maior que o último enviado a esse destinatário) | não |
| `0x06` | `DUPLICATE_CLIENT_ID` | sim |
| `0x07` | `SERVER_FULL` | sim |

Depois de um erro fatal, o servidor envia `DISCONNECT` (reason `0x01 PROTOCOL_ERROR`) e
fecha a conexão. Quando o servidor é encerrado, ele envia `DISCONNECT` com reason
`0x02 SERVER_SHUTDOWN` a todos os clientes.

## 5. Frame E2E (`0x10`)

Formato do enunciado, precedido apenas do byte de tipo:
```
0x10 || nonce (12B) || sender_id (16B) || recipient_id (16B) || seq_no (8B) || ciphertext || tag (16B)
nonce = IV_base_send (4B) || seq_no (8B)
AAD   = sender_id || recipient_id || seq_no
```

- Plaintext: de 0 a 4096 bytes. O corpo (sem o byte de tipo) tem de 68 a 4164 bytes.
- O servidor só lê o cabeçalho de roteamento e encaminha o frame **byte a byte
  idêntico** ao destinatário. Ele nunca decifra o conteúdo.
- Verificações no servidor: tamanho (fatal), `sender_id == client_id` da sessão,
  destinatário conectado e diferente do remetente, e anti-replay por par
  (`seq_no` > último `seq_no` enviado a esse destinatário).
  - O anti-replay no servidor pode ser desligado com `--no-replay-check`, para
    demonstrar a rejeição no cliente destinatário.

## 6. Encerramento

Quando um cliente desconecta (ou é desconectado), a sessão sai imediatamente da tabela
`sessions`, os contadores anti-replay que os outros clientes tinham com ele são
descartados e todos os clientes restantes recebem `PEER_LEFT`.
