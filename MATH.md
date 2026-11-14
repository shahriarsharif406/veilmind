# The mathematics behind Veilmind

## 1. The field GF(2^8)
Bytes are elements of GF(2^8) = F_2[x] / (x^8 + x^4 + x^3 + x + 1), the same field AES uses.
Addition is XOR. Multiplication is polynomial multiplication reduced by the polynomial above.
Every non-zero element has an inverse: a^(-1) = a^254, because the multiplicative group has order 255.

`gf_mul` in `veilcore/src/main.rs` computes this with masks, not branches or lookup tables, so its
timing and memory access pattern do not depend on the secret. Tests check it against the FIPS-197
vector `{57} x {83} = {c1}` and against a table-based reference for all 65,536 input pairs.

## 2. Shamir's (k, n) secret sharing
For each byte s of the 32-byte master key pick a random polynomial of degree k-1 over GF(2^8):

    f(x) = s + a_1 x + ... + a_(k-1) x^(k-1)      (a_i uniformly random)

Share i is the point (x_i, f(x_i)) with x_i = 1..n. We use k = 3, n = 5.

**Reconstruction** is Lagrange interpolation at x = 0:

    s = f(0) = sum_i  y_i * prod_(j != i)  x_j / (x_i + x_j)

(in characteristic 2, subtraction equals addition).

**Why fewer than k shares reveal nothing.** Given k-1 points, every possible secret s' is consistent
with exactly one polynomial through those points plus (0, s'). All 256 values of s' are equally likely,
so the shares carry zero information about s. This is information-theoretic security: it holds even
against an attacker with unlimited computing power. The test
`fewer_than_k_shares_do_not_reveal_secret` shows 2 shares rebuild a different, useless value.

## 3. Authenticated encryption
Sensitive values are sealed with AES-256-GCM using a fresh random 96-bit nonce per value.
The token name (for example `⟦CARD_1⟧`) is passed as associated data, so a ciphertext only opens under
the exact token it was created for. Any change to the ciphertext, the token or the key makes the 128-bit
authentication tag fail.

## 4. Threat model

| Attacker | What they get | Outcome |
|---|---|---|
| The LLM provider | The exact request: masked text only | No plaintext, no key, no shares |
| Someone holding 1 or 2 shares | Random-looking bytes | Learns nothing about the key (section 2) |
| A model that rewrites or invents a token | A token not in the local table, or a failed tag | Left sealed, flagged in the UI. Never guessed |
| Token swapping | Ciphertext from one token placed under another | Tag check fails (associated data differs) |
| Cache-timing on the field arithmetic | Timing of `gf_mul` | No secret-dependent branches or table lookups |
| Bug that would leak data in the request | Plaintext or share inside the outgoing bytes | The leak check aborts the request (fails closed) |

**Out of scope (honest limits).** A compromised local machine that holds 3 shares at the same time.
Sensitive values the detector does not recognise. Anything the user chooses to leave unsealed.
Without fully homomorphic encryption the model cannot compute on the hidden values themselves.
