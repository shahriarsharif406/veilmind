//! veilcore: the only component that ever touches the master key.
//!
//! Commands (all I/O is hex / text on stdin+stdout, nothing is written to disk):
//!   veilcore split <n> <k>   -> prints key fingerprint, then n Shamir shares (one per line)
//!   veilcore seal            -> stdin: line1 shares, line2 aad(hex), line3 plaintext(hex) -> nonce||ct (hex)
//!   veilcore open            -> stdin: line1 shares, line2 aad(hex), line3 nonce||ct (hex) -> plaintext (hex)
//!
//! The master key is rebuilt from k shares in memory, used once, then zeroized.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::io::{self, BufRead};
use zeroize::Zeroize;

const KEY_LEN: usize = 32;

// ---------- GF(256), AES polynomial 0x11b ----------
// Constant-time: no secret-dependent branches and no LOG/EXP table lookups. Table-based GF(256)
// code leaks through cache timing (this class of bug was CVE-2023-25000 in HashiCorp Vault's Shamir).
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        p ^= a & 0u8.wrapping_sub(b & 1); // add `a` iff low bit of b is set
        let carry = 0u8.wrapping_sub(a >> 7); // 0xFF iff a's top bit is set
        a = (a << 1) ^ (0x1b & carry); // reduce by x^8 + x^4 + x^3 + x + 1
        b >>= 1;
    }
    p
}

fn gf_inv(a: u8) -> u8 {
    // a^254 in GF(256); constant work, no table lookups indexed by secret data
    let mut r = 1u8;
    let mut base = a;
    let mut e = 254u8;
    while e > 0 {
        if e & 1 != 0 {
            r = gf_mul(r, base);
        }
        base = gf_mul(base, base);
        e >>= 1;
    }
    r
}

/// Split `secret` into `n` shares, any `k` reconstruct. Share = [x, y_0..y_len].
fn split(secret: &[u8], n: usize, k: usize) -> Vec<Vec<u8>> {
    assert!(k >= 2 && k <= n && n <= 255, "need 2 <= k <= n <= 255");
    let mut shares: Vec<Vec<u8>> = (1..=n).map(|x| vec![x as u8]).collect();
    let mut coeffs = vec![0u8; k];
    for &byte in secret {
        coeffs[0] = byte;
        OsRng.fill_bytes(&mut coeffs[1..]);
        for share in shares.iter_mut() {
            let x = share[0];
            // Horner evaluation
            let mut y = 0u8;
            for c in coeffs.iter().rev() {
                y = gf_mul(y, x) ^ c;
            }
            share.push(y);
        }
    }
    coeffs.zeroize();
    shares
}

/// Lagrange interpolation at x = 0.
fn combine(shares: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    if shares.len() < 2 {
        return Err("need at least 2 shares".into());
    }
    let len = shares[0].len();
    if len < 2 || shares.iter().any(|s| s.len() != len) {
        return Err("malformed shares".into());
    }
    let xs: Vec<u8> = shares.iter().map(|s| s[0]).collect();
    for (i, x) in xs.iter().enumerate() {
        if *x == 0 || xs[..i].contains(x) {
            return Err("duplicate or zero share index".into());
        }
    }
    let mut out = vec![0u8; len - 1];
    for (i, si) in shares.iter().enumerate() {
        let mut num = 1u8;
        let mut den = 1u8;
        for (j, sj) in shares.iter().enumerate() {
            if i != j {
                num = gf_mul(num, sj[0]);
                den = gf_mul(den, si[0] ^ sj[0]);
            }
        }
        let l = gf_mul(num, gf_inv(den));
        for b in 0..out.len() {
            out[b] ^= gf_mul(si[b + 1], l);
        }
    }
    Ok(out)
}

fn fingerprint(key: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"veilmind-fp-v1");
    h.update(key);
    hex::encode(&h.finalize()[..6])
}

fn parse_shares(line: &str) -> Result<Vec<Vec<u8>>, String> {
    line.split_whitespace()
        .map(|t| hex::decode(t).map_err(|e| format!("bad share hex: {e}")))
        .collect()
}

fn seal(key: &[u8], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: pt, aad })
        .map_err(|_| "encrypt failed".to_string())?;
    let mut out = nonce.to_vec();
    out.extend(ct);
    Ok(out)
}

fn open(key: &[u8], aad: &[u8], blob: &[u8]) -> Result<Vec<u8>, String> {
    if blob.len() < 12 + 16 {
        return Err("ciphertext too short".into());
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(&blob[..12]), Payload { msg: &blob[12..], aad })
        .map_err(|_| "authentication failed (wrong key, tampered data or wrong binding)".to_string())
}

fn read_lines() -> Vec<String> {
    io::stdin().lock().lines().map_while(Result::ok).collect()
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("split") => {
            let n: usize = args.get(2).and_then(|s| s.parse().ok()).ok_or("usage: split <n> <k>")?;
            let k: usize = args.get(3).and_then(|s| s.parse().ok()).ok_or("usage: split <n> <k>")?;
            if !(2 <= k && k <= n && n <= 255) {
                return Err("need 2 <= k <= n <= 255".into());
            }
            let mut key = [0u8; KEY_LEN];
            OsRng.fill_bytes(&mut key);
            println!("{}", fingerprint(&key));
            for s in split(&key, n, k) {
                println!("{}", hex::encode(s));
            }
            key.zeroize(); // the master key exists only inside this process, only for this call
            Ok(())
        }
        Some(cmd @ ("seal" | "open")) => {
            let lines = read_lines();
            if lines.len() < 3 {
                return Err("expected 3 stdin lines: shares, aad(hex), payload(hex)".into());
            }
            let mut key = combine(&parse_shares(&lines[0])?)?;
            if key.len() != KEY_LEN {
                key.zeroize();
                return Err("reconstructed key has wrong length".into());
            }
            let aad = hex::decode(lines[1].trim()).map_err(|e| e.to_string())?;
            let payload = hex::decode(lines[2].trim()).map_err(|e| e.to_string())?;
            let res = if cmd == "seal" { seal(&key, &aad, &payload) } else { open(&key, &aad, &payload) };
            key.zeroize();
            println!("{}", hex::encode(res?));
            Ok(())
        }
        Some("fingerprint") => {
            let lines = read_lines();
            let mut key = combine(&parse_shares(lines.first().ok_or("no shares")?)?)?;
            println!("{}", fingerprint(&key));
            key.zeroize();
            Ok(())
        }
        _ => Err("usage: veilcore split <n> <k> | seal | open | fingerprint".into()),
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Table-based reference (log/exp, generator 3). Used ONLY in tests to check the constant-time code.
    fn ref_mul(a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            return 0;
        }
        let (mut exp, mut log) = ([0u8; 255], [0usize; 256]);
        let mut x = 1u8;
        for i in 0..255 {
            exp[i] = x;
            log[x as usize] = i;
            let x2 = (x << 1) ^ if x & 0x80 != 0 { 0x1b } else { 0 };
            x = x2 ^ x; // multiply by 3
        }
        exp[(log[a as usize] + log[b as usize]) % 255]
    }

    #[test]
    fn gf_mul_matches_aes_spec_vector() {
        // FIPS-197 section 4.2: {57} x {83} = {c1}
        assert_eq!(gf_mul(0x57, 0x83), 0xc1);
    }

    #[test]
    fn gf_mul_matches_reference_for_all_65536_pairs() {
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert_eq!(gf_mul(a, b), ref_mul(a, b), "a={a} b={b}");
            }
        }
    }

    #[test]
    fn gf_inverse_is_correct() {
        for a in 1..=255u8 {
            assert_eq!(gf_mul(a, gf_inv(a)), 1);
        }
    }

    #[test]
    fn any_k_of_n_reconstructs() {
        let secret: Vec<u8> = (0..32).map(|i| (i * 7 + 3) as u8).collect();
        let shares = split(&secret, 5, 3);
        for a in 0..5 {
            for b in (a + 1)..5 {
                for c in (b + 1)..5 {
                    let got = combine(&[shares[a].clone(), shares[b].clone(), shares[c].clone()]).unwrap();
                    assert_eq!(got, secret);
                }
            }
        }
    }

    #[test]
    fn fewer_than_k_shares_do_not_reveal_secret() {
        let secret = vec![0xAB; 32];
        let shares = split(&secret, 5, 3);
        let got = combine(&[shares[0].clone(), shares[1].clone()]).unwrap();
        assert_ne!(got, secret);
    }

    #[test]
    fn aead_roundtrip_and_binding() {
        let key = [9u8; 32];
        let blob = seal(&key, b"VM_1", b"4521-8890-1177").unwrap();
        assert_eq!(open(&key, b"VM_1", &blob).unwrap(), b"4521-8890-1177");
        assert!(open(&key, b"VM_2", &blob).is_err(), "wrong aad must fail");
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(open(&key, b"VM_1", &bad).is_err(), "tamper must fail");
        assert!(open(&[1u8; 32], b"VM_1", &blob).is_err(), "wrong key must fail");
    }

    #[test]
    fn duplicate_shares_rejected() {
        let shares = split(&[1u8; 32], 5, 3);
        assert!(combine(&[shares[0].clone(), shares[0].clone()]).is_err());
    }
}
