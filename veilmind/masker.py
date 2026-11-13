"""Finds sensitive values in text and swaps them for opaque tokens like ⟦EMAIL_1⟧."""
from __future__ import annotations

import re
from dataclasses import dataclass

# (kind, regex, group). Earlier entries win on overlap.
_PATTERNS: list[tuple[str, re.Pattern, int]] = [
    ("SECRET", re.compile(r"\[\[(.+?)\]\]"), 1),  # user-marked: [[anything]]
    ("APIKEY", re.compile(r"\b(?:sk-|AIza|ghp_|xox[bp]-)[A-Za-z0-9_\-]{16,}\b"), 0),
    ("EMAIL", re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"), 0),
    ("IBAN", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"), 0),
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), 0),
    ("CARD", re.compile(r"\b\d(?:[ -]?\d){12,18}\b"), 0),
    ("PHONE", re.compile(r"(?<!\d)(?:\+?880[ -]?|0)1[3-9][\d -]{8,10}\d(?!\d)|(?<!\d)\+\d{1,3}[ -]?\d[\d -]{7,12}\d(?!\d)"), 0),
    ("ACCOUNT", re.compile(r"\b\d{9,16}\b"), 0),
    ("NAME", re.compile(r"(?:my name is|I am|I'm|name:)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)"), 1),
]


def _luhn(s: str) -> bool:
    d = [int(c) for c in s if c.isdigit()]
    if not 13 <= len(d) <= 19:
        return False
    total = 0
    for i, n in enumerate(reversed(d)):
        if i % 2:
            n = n * 2 - 9 if n * 2 > 9 else n * 2
        total += n
    return total % 10 == 0


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    kind: str
    value: str


def find_spans(text: str) -> list[Span]:
    taken: list[Span] = []
    for kind, rx, grp in _PATTERNS:
        for m in rx.finditer(text):
            s, e = m.span(grp)
            val = text[s:e]
            if kind == "CARD" and not _luhn(val):
                continue
            if any(s < t.end and e > t.start for t in taken):
                continue
            taken.append(Span(s, e, kind, val))
    return sorted(taken, key=lambda x: x.start)


def mask(text: str, seal_fn) -> tuple[str, dict[str, dict]]:
    """Return (masked_text, table). `seal_fn(value, aad) -> ciphertext_hex` runs in the Rust core.

    table[token] = {"kind", "cipher"}; the plaintext is *not* kept anywhere in Python.
    For [[...]] spans the brackets are consumed with the value.
    """
    spans = find_spans(text)
    table: dict[str, dict] = {}
    counters: dict[str, int] = {}
    seen: dict[tuple[str, str], str] = {}
    out, cur = [], 0
    for sp in spans:
        key = (sp.kind, sp.value)
        if key not in seen:
            counters[sp.kind] = counters.get(sp.kind, 0) + 1
            token = f"⟦{sp.kind}_{counters[sp.kind]}⟧"
            seen[key] = token
            table[token] = {"kind": sp.kind, "cipher": seal_fn(sp.value, token)}
        start, end = sp.start, sp.end
        if sp.kind == "SECRET":  # swallow the [[ ]]
            start, end = start - 2, end + 2
        out.append(text[cur:start])
        out.append(seen[key])
        cur = end
    out.append(text[cur:])
    return "".join(out), table


_TOKEN = re.compile(r"⟦[A-Z]+_\d+⟧")


def unmask(text: str, table: dict[str, dict], open_fn) -> tuple[str, list[dict], list[dict]]:
    """Replace tokens in the model's reply by decrypting locally. Unknown tokens are flagged, not guessed.

    Returns (plain_text, events, segments); segments mark which parts were opened locally (for the UI).
    """
    events: list[dict] = []
    segs: list[dict] = []
    out, cur = [], 0
    for m in _TOKEN.finditer(text):
        tok = m.group(0)
        if m.start() > cur:
            segs.append({"t": text[cur:m.start()], "s": "plain"})
        if tok not in table:
            events.append({"token": tok, "status": "unknown"})
            val, st = tok, "unknown"
        else:
            try:
                val, st = open_fn(table[tok]["cipher"], tok), "opened"
                events.append({"token": tok, "status": "opened"})
            except Exception as e:  # locked vault, tamper, wrong key
                val, st = tok, "sealed"
                events.append({"token": tok, "status": "sealed", "reason": str(e)})
        segs.append({"t": val, "s": st, "token": tok})
        out.append(text[cur:m.start()])
        out.append(val)
        cur = m.end()
    if cur < len(text):
        segs.append({"t": text[cur:], "s": "plain"})
    out.append(text[cur:])
    return "".join(out), events, segs
