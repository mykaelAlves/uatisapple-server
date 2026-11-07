# Uatisapple Server

Servidor relay da mensageria segura multi-cliente Uatisapple, com criptografia ponta a
ponta (E2E). O servidor autentica o handshake com RSA-PSS, distribui as chaves públicas
X25519 dos clientes e encaminha os frames E2E **sem conseguir decifrá-los**.

O formato de bytes de todas as mensagens está em [PROTOCOL.md](PROTOCOL.md).

## Como rodar

```bash
uv run main.py                      # 127.0.0.1:6767
uv run main.py --host 0.0.0.0 --port 6767 --max-clients 50
uv run main.py --no-replay-check    # deixa o anti-replay só para o cliente destinatário
```

Na primeira execução, o servidor gera `certs/server.key` (permissão 0600, **nunca
versionar**) e `certs/server.crt`. Distribua o `server.crt` aos clientes por fora do
canal, para que eles possam fazer o *pinning*. O fingerprint SHA-256 do certificado
aparece no log quando o servidor sobe.

## Testes

```bash
uv run pytest
```

Os testes de integração ([tests/test_server.py](tests/test_server.py)) sobem o servidor
e usam um cliente de referência ([tests/fake_client.py](tests/fake_client.py)) para
cobrir: handshake e pinning, distribuição de chaves, troca E2E entre vários clientes,
bitflip, replay, framing inválido, reconexão e limpeza de sessão.

## Estrutura

| Arquivo | Responsabilidade |
|---------|------------------|
| [src/server.py](src/server.py) | `ServerRelay`: conexões, handshake, tabela `sessions`, relay e mensagens administrativas |
| [src/client_session.py](src/client_session.py) | `ClientSession`: entrada da tabela `sessions` |
| [src/protocol.py](src/protocol.py) | Tipos de mensagem, limites, parsing e serialização |
| [src/crypto.py](src/crypto.py) | Certificado/RSA-PSS, X25519 + HKDF (`Key_S2C`), AES-GCM administrativo |
| [src/network.py](src/network.py) | Framing com prefixo de 4 bytes e detecção de framing inválido |

## Política de logs

O servidor registra apenas eventos de conexão e desconexão, `client_id`, tamanhos de
frame, motivos de rejeição e fingerprints de chaves. Ele nunca registra chaves
privadas, segredos, salts, nonces ou conteúdo de mensagens.
