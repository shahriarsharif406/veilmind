"""Thin, audited bridge to the Rust core (`veilcore`).

Python never sees the master key. It only holds Shamir *shares* and hands k of them to the
Rust process, which rebuilds the key in memory, uses it once and zeroizes it.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

N_SHARES = 5
THRESHOLD = 3
HOLDERS = ["This device", "Phone", "USB key", "Cloud vault", "Recovery card"]

_ROOT = Path(__file__).resolve().parent.parent


def _binary() -> str:
    for cand in (os.environ.get("VEILCORE_BIN"), _ROOT / "bin" / "veilcore",
                 _ROOT / "veilcore" / "target" / "release" / "veilcore"):
        if cand and Path(cand).exists():
            return str(cand)
    raise FileNotFoundError("veilcore binary not found. Run: cargo build --release --manifest-path veilcore/Cargo.toml")


def _run(args: list[str], stdin: str = "") -> list[str]:
    p = subprocess.run([_binary(), *args], input=stdin, capture_output=True, text=True, timeout=15)
    if p.returncode != 0:
        raise VaultError(p.stderr.strip() or "veilcore failed")
    return p.stdout.split()


class VaultError(Exception):
    pass


class Vault:
    """Holds the 5 shares and which holders are currently 'present' (unlocked)."""

    def __init__(self) -> None:
        self.rotate()

    def rotate(self) -> None:
        out = _run(["split", str(N_SHARES), str(THRESHOLD)])
        self.fingerprint, self._shares = out[0], out[1:]
        self.present = set(range(THRESHOLD))  # first k holders present by default

    def toggle(self, idx: int) -> None:
        if not 0 <= idx < N_SHARES:
            raise VaultError("bad holder index")
        self.present.symmetric_difference_update({idx})

    @property
    def unlocked(self) -> bool:
        return len(self.present) >= THRESHOLD

    def _present_shares(self) -> str:
        if not self.unlocked:
            raise VaultError(f"vault locked: {len(self.present)} of {THRESHOLD} required key holders present")
        return " ".join(self._shares[i] for i in sorted(self.present))

    def seal(self, plaintext: str, aad: str) -> str:
        stdin = f"{self._present_shares()}\n{aad.encode().hex()}\n{plaintext.encode().hex()}\n"
        return _run(["seal"], stdin)[0]

    def open(self, ciphertext_hex: str, aad: str) -> str:
        stdin = f"{self._present_shares()}\n{aad.encode().hex()}\n{ciphertext_hex}\n"
        return bytes.fromhex(_run(["open"], stdin)[0]).decode()

    def share_hexes(self) -> list[str]:  # for the leak check only; never sent anywhere
        return list(self._shares)

    def state(self) -> dict:
        return {
            "fingerprint": self.fingerprint,
            "threshold": THRESHOLD,
            "holders": [{"name": n, "present": i in self.present} for i, n in enumerate(HOLDERS)],
            "unlocked": self.unlocked,
        }
