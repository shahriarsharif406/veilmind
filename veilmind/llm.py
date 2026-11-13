"""The ONLY module that talks to the model provider. It receives masked text and nothing else."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
SYSTEM = (
    "You are a careful assistant. The user's text contains opaque encrypted references written like "
    "⟦EMAIL_1⟧ or ⟦CARD_2⟧. You cannot know what they contain. When you refer to one in your answer, "
    "copy it exactly, character for character, including the ⟦ ⟧ brackets. Never guess or invent the "
    "hidden value, and never invent new references."
)


def build_request(masked_text: str) -> dict:
    return {
        "system_instruction": {"parts": [{"text": SYSTEM}]},
        "contents": [{"role": "user", "parts": [{"text": masked_text}]}],
        "generationConfig": {"temperature": 0.3},
    }


def endpoint() -> str:
    return f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:generateContent"


def have_key() -> bool:
    return bool(os.environ.get("GEMINI_API_KEY"))


def send(body: dict) -> tuple[str, dict]:
    """Returns (reply_text, raw_response). Falls back to a clearly-labelled mock if no key is set."""
    if not have_key():
        return _mock(body), {"mock": True}
    req = urllib.request.Request(
        endpoint(), data=json.dumps(body).encode(), method="POST",
        headers={"Content-Type": "application/json", "x-goog-api-key": os.environ["GEMINI_API_KEY"]},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = json.load(r)
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:400]
        raise RuntimeError(f"Gemini API error {e.code}: {detail}") from None
    try:
        text = "".join(p.get("text", "") for p in raw["candidates"][0]["content"]["parts"])
    except (KeyError, IndexError):
        raise RuntimeError("Gemini returned no text (possibly blocked by safety filters)") from None
    return text, raw


def _mock(body: dict) -> str:
    import re
    msg = body["contents"][0]["parts"][0]["text"]
    toks = list(dict.fromkeys(re.findall(r"⟦[A-Z]+_\d+⟧", msg)))
    if not toks:
        return "[MOCK reply: no GEMINI_API_KEY set] I received your message. It had no protected values."
    return ("[MOCK reply: no GEMINI_API_KEY set] I can see " + str(len(toks)) +
            " protected reference(s): " + ", ".join(toks) + ". I can't read them, but I can refer to them: "
            f"for example, please confirm that {toks[0]} is correct before proceeding.")
