"""mask -> leak-check -> model -> unmask. All proof artefacts are returned for the UI."""
from __future__ import annotations

import json
import time

from . import llm, masker
from .vault import Vault, VaultError


def leak_check(wire_body: str, plaintexts: list[str], shares: list[str]) -> dict:
    """Scan the exact bytes about to leave the machine for any plaintext value or key share."""
    hits = [p for p in plaintexts if len(p) >= 3 and p in wire_body]
    share_hits = [s for s in shares if s in wire_body]
    return {"values_checked": len(plaintexts), "shares_checked": len(shares),
            "leaks": len(hits) + len(share_hits)}


def ask(vault: Vault, text: str) -> dict:
    t0 = time.time()
    spans = masker.find_spans(text)
    plaintexts = [s.value for s in spans]
    try:
        masked, table = masker.mask(text, vault.seal)
    except VaultError as e:
        return {"ok": False, "error": str(e), "stage": "seal"}

    body = llm.build_request(masked)
    wire = json.dumps(body, ensure_ascii=False, indent=2)
    check = leak_check(wire, plaintexts, vault.share_hexes())
    if check["leaks"]:  # fail closed
        return {"ok": False, "error": "Leak check failed: refusing to send.", "stage": "leak", "check": check}

    try:
        reply, raw = llm.send(body)
    except Exception as e:
        return {"ok": False, "error": str(e), "stage": "model", "masked": masked, "wire": wire, "check": check}

    opened, events, segs = masker.unmask(reply, table, vault.open)
    return {
        "ok": True,
        "mock": bool(raw.get("mock")),
        "model": llm.MODEL,
        "endpoint": llm.endpoint(),
        "original": text,
        "masked": masked,
        "wire": wire,
        "model_reply": reply,
        "final": opened,
        "final_segments": segs,
        "spans": [{"start": sp.start - (2 if sp.kind == "SECRET" else 0),
                   "end": sp.end + (2 if sp.kind == "SECRET" else 0), "kind": sp.kind} for sp in spans],
        "vault": [{"token": t, "kind": v["kind"], "cipher": v["cipher"]} for t, v in table.items()],
        "events": events,
        "check": check,
        "ms": int((time.time() - t0) * 1000),
    }
