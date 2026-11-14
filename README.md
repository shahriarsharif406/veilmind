# Veilmind

**Ask Gemini without telling it anything.** Veilmind is a local AI agent whose inputs are sealed before they leave your computer. The LLM only ever sees opaque references, and the master key is never known to the agent or to the API provider.

Built for the *Mathematics for systems security* hackathon, **AI pipeline track**.

## How it works

```
 your text ──► [find sensitive values] ──► seal each one (AES-256-GCM, Rust) ──► ⟦CARD_1⟧ references
                                                                                      │
                          leak check on the exact outgoing bytes (fails closed)  ◄────┘
                                                                                      │
                                         Gemini API sees only: "my card ⟦CARD_1⟧ …"  ▼
 final answer ◄── open references locally (key rebuilt from 3 of 5 shares, then wiped) ◄── reply with ⟦CARD_1⟧
```

1. **Master key, split.** `veilcore` (Rust) generates a 256-bit key and splits it with **Shamir's Secret Sharing over GF(256)**: 5 shares, any 3 rebuild it. The key itself is never printed and never leaves that process.
2. **Seal.** Each sensitive value (email, card, phone, name, IBAN, API key, or anything in `[[double brackets]]`) is encrypted with AES-256-GCM. The token name is bound as authenticated data, so sealed values cannot be swapped between tokens.
3. **Send.** Gemini receives masked text such as `my card ⟦CARD_1⟧`. Before sending, Veilmind scans the exact request bytes for every plaintext value and every key share. A single hit aborts the request.
4. **Open.** The reply contains the same references. They are decrypted locally. The key is rebuilt from the shares in memory for that one operation and then zeroized.
5. **Quorum is real.** In the UI, switch key holders off. With fewer than 3 present, the vault is locked: nothing can be sealed or opened.

## Run it

```bash
cargo build --release --manifest-path veilcore/Cargo.toml     # Windows, macOS, Linux
cp .env.example .env          # Windows: copy .env.example .env   (then paste your Gemini key into .env)
python3 -m veilmind           # Windows: python -m veilmind   ->  http://127.0.0.1:8765 (loopback only)
```

No key? It runs in a clearly labelled demo mode with simulated replies, so you can still see the sealing, the leak check and the vault.

Tests: `cargo test --manifest-path veilcore/Cargo.toml` and `python3 -m pytest tests`.

## Stack

- **Rust** (`veilcore`): GF(256) Shamir, AES-256-GCM (`aes-gcm`), OS randomness, `zeroize`.
- **Python** (standard library only, plus the Rust binary): masking, pipeline, Gemini REST client, loopback web UI.
- **Gemini API** for the agent.

## Related open source, and how Veilmind differs

- **Microsoft Presidio** detects and anonymizes PII with regex and NER models. Its built-in reversible operator is AES encrypt/decrypt, and the mapping store is left for you to build. Veilmind adds a split master key (Shamir, k of n), token-bound authenticated encryption, and an outgoing-request leak check.
- **Reversible scrubbers and gateways** (for example `pii-airlock`, built on Presidio) keep a local placeholder-to-value mapping file. In Veilmind there is no plaintext mapping: values exist only as AES-GCM ciphertext, and opening one needs a quorum of key holders.
- **HashiCorp Vault's Shamir** uses GF(256) and was affected by a cache-timing flaw (CVE-2023-25000) because of precomputed lookup tables. Veilmind's field multiply is branch-free and table-free, and tested against a reference for all 65,536 input pairs.

See [MATH.md](MATH.md) for the mathematics and threat model.

## Honest limits

- Without fully homomorphic encryption an LLM cannot reason over true ciphertext. Veilmind keeps secrets *out* of the model's view: it reasons over opaque references and the answer is opened locally. If a task needs the model to read the value itself, that value must not be sealed.
- Detection is pattern-based (plus your `[[ ]]` markers). Anything it does not recognise is sent as written.
- In this demo all five shares live inside one local process so the quorum can be shown on screen. In a real deployment each share sits with a different holder (device, phone, hardware key).
- The AES-GCM and Shamir pieces are standard constructions, not a new cipher.
