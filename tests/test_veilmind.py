import json

import pytest

from veilmind import llm, masker, pipeline
from veilmind.vault import Vault, VaultError

TEXT = ("Hi, my name is Rahim Uddin. Email rahim@example.com, card 4111 1111 1111 1111, "
        "phone +8801712345678. Secret is [[hunter2-is-bad]]. Summarise my situation.")


@pytest.fixture(scope="module")
def vault():
    return Vault()


def test_finds_expected_kinds():
    kinds = {s.kind for s in masker.find_spans(TEXT)}
    assert {"NAME", "EMAIL", "CARD", "PHONE", "SECRET"} <= kinds


def test_luhn_rejects_random_digits():
    assert not any(s.kind == "CARD" for s in masker.find_spans("order 1234 5678 9012 3456"))


def test_wire_has_no_plaintext_and_roundtrip(vault, monkeypatch):
    seen = {}

    def fake_send(body):
        seen["wire"] = json.dumps(body, ensure_ascii=False)
        user = body["contents"][0]["parts"][0]["text"]
        return f"Echo: {user}", {}

    monkeypatch.setattr(llm, "send", fake_send)
    r = pipeline.ask(vault, TEXT)
    assert r["ok"] and r["check"]["leaks"] == 0
    for secret in ("rahim@example.com", "4111 1111 1111 1111", "+8801712345678", "hunter2-is-bad", "Rahim Uddin"):
        assert secret not in seen["wire"]
        assert secret in r["final"]          # decrypted locally from the model's reply
    assert all(e["status"] == "opened" for e in r["events"])


def test_locked_vault_refuses_and_tokens_stay_sealed(monkeypatch):
    v = Vault()
    monkeypatch.setattr(llm, "send", lambda b: (b["contents"][0]["parts"][0]["text"], {}))
    ok = pipeline.ask(v, "mail a@b.co please")
    assert ok["ok"]
    v.toggle(0)  # drop to 2 of 3 holders
    assert not v.unlocked
    r = pipeline.ask(v, "mail a@b.co please")
    assert not r["ok"] and r["stage"] == "seal"


def test_unlock_changes_with_any_three_holders():
    v = Vault()
    for i in range(5):
        if i not in v.present:
            v.toggle(i)
    for i in (0, 1):
        v.toggle(i)  # present = {2,3,4}
    assert v.unlocked
    assert v.open(v.seal("x@y.zz", "AAD"), "AAD") == "x@y.zz"


def test_aad_binding_blocks_token_swapping(vault):
    c = vault.seal("secret-one", "⟦SECRET_1⟧")
    with pytest.raises(Exception):
        vault.open(c, "⟦SECRET_2⟧")


def test_rotation_invalidates_old_ciphertext():
    v = Vault()
    c = v.seal("abc@def.gh", "T")
    v.rotate()
    with pytest.raises(Exception):
        v.open(c, "T")


def test_unknown_tokens_are_flagged_not_invented(vault):
    out, ev, _ = masker.unmask("see ⟦EMAIL_9⟧", {}, vault.open)
    assert out == "see ⟦EMAIL_9⟧" and ev[0]["status"] == "unknown"


def test_card_span_has_no_trailing_space():
    sp = [s for s in masker.find_spans("card 4111 1111 1111 1111 email a@b.co") if s.kind == "CARD"][0]
    assert sp.value == "4111 1111 1111 1111"
