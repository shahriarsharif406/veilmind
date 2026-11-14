/* Veilmind browser engine: the same maths as the Rust core, in JavaScript.
   Shamir over GF(2^8) (AES polynomial 0x11b), 5 shares / threshold 3, AES-256-GCM via WebCrypto.
   Used only by the hosted demo. The full app uses the Rust core and calls Gemini. */
const VeilEngine = (() => {
  const N = 5, K = 3;
  const HOLDERS = ["This device", "Phone", "USB key", "Cloud vault", "Recovery card"];
  const MODEL = "gemini-2.5-flash";
  const SYSTEM = "You are a careful assistant. The user's text contains opaque encrypted references written like " +
    "⟦EMAIL_1⟧ or ⟦CARD_2⟧. You cannot know what they contain. When you refer to one in your answer, " +
    "copy it exactly, character for character, including the ⟦ ⟧ brackets. Never guess or invent the " +
    "hidden value, and never invent new references.";
  const cr = globalThis.crypto;
  const enc = new TextEncoder(), dec = new TextDecoder();
  const hex = b => Array.from(b, x => x.toString(16).padStart(2, "0")).join("");
  const unhex = h => Uint8Array.from(h.match(/../g) || [], x => parseInt(x, 16));

  // Constant-time, branch-free multiply in GF(2^8), same as veilcore/src/main.rs
  function gfMul(a, b) {
    let p = 0;
    for (let i = 0; i < 8; i++) {
      p ^= a & (0 - (b & 1)) & 0xff;
      const carry = (0 - (a >> 7)) & 0xff;
      a = ((a << 1) & 0xff) ^ (0x1b & carry);
      b >>= 1;
    }
    return p;
  }
  function gfInv(a) { let r = 1; for (let i = 0; i < 254; i++) r = gfMul(r, a); return r; } // a^254

  function split(secret, n = N, k = K) {
    const shares = Array.from({ length: n }, (_, i) => { const s = new Uint8Array(secret.length + 1); s[0] = i + 1; return s; });
    for (let j = 0; j < secret.length; j++) {
      const c = cr.getRandomValues(new Uint8Array(k - 1));
      for (let i = 0; i < n; i++) {
        const x = i + 1; let y = secret[j], xp = 1;
        for (let d = 0; d < k - 1; d++) { xp = gfMul(xp, x); y ^= gfMul(c[d], xp); }
        shares[i][j + 1] = y;
      }
    }
    return shares;
  }
  function combine(shares) { // Lagrange interpolation at x = 0
    const len = shares[0].length - 1, out = new Uint8Array(len);
    for (let j = 0; j < len; j++) {
      let acc = 0;
      for (let i = 0; i < shares.length; i++) {
        let num = 1, den = 1;
        for (let m = 0; m < shares.length; m++) if (m !== i) { num = gfMul(num, shares[m][0]); den = gfMul(den, shares[i][0] ^ shares[m][0]); }
        acc ^= gfMul(shares[i][j + 1], gfMul(num, gfInv(den)));
      }
      out[j] = acc;
    }
    return out;
  }

  class Vault {
    constructor() { this.ready = this.rotate(); }
    async rotate() {
      const key = cr.getRandomValues(new Uint8Array(32));
      this.shares = split(key, N, K);
      this.fingerprint = hex(new Uint8Array(await cr.subtle.digest("SHA-256", key))).slice(0, 12);
      this.present = new Set([0, 1, 2]);
    }
    toggle(i) { this.present.has(i) ? this.present.delete(i) : this.present.add(i); }
    get unlocked() { return this.present.size >= K; }
    shareHexes() { return this.shares.map(hex); }
    state() {
      return { fingerprint: this.fingerprint, threshold: K, live: false, model: MODEL,
        holders: HOLDERS.map((name, i) => ({ name, present: this.present.has(i) })), unlocked: this.unlocked };
    }
    async _key() {
      if (!this.unlocked) throw new Error(`vault locked: ${this.present.size} of ${K} required key holders present`);
      const use = [...this.present].sort().slice(0, K).map(i => this.shares[i]);
      const raw = combine(use);
      const key = await cr.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
      raw.fill(0); // best effort in JS
      return key;
    }
    async seal(plain, aad) {
      const key = await this._key(), nonce = cr.getRandomValues(new Uint8Array(12));
      const ct = new Uint8Array(await cr.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: enc.encode(aad) }, key, enc.encode(plain)));
      return hex(nonce) + hex(ct);
    }
    async open(cipherHex, aad) {
      const key = await this._key(), b = unhex(cipherHex);
      const pt = await cr.subtle.decrypt({ name: "AES-GCM", iv: b.slice(0, 12), additionalData: enc.encode(aad) }, key, b.slice(12));
      return dec.decode(pt);
    }
  }

  // ---- masker (port of veilmind/masker.py) ----
  const PATTERNS = [
    ["SECRET", /\[\[(.+?)\]\]/g, 1],
    ["APIKEY", /\b(?:sk-|AIza|ghp_|xox[bp]-)[A-Za-z0-9_\-]{16,}\b/g, 0],
    ["EMAIL", /[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/g, 0],
    ["IBAN", /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g, 0],
    ["SSN", /\b\d{3}-\d{2}-\d{4}\b/g, 0],
    ["CARD", /\b\d(?:[ -]?\d){12,18}\b/g, 0],
    ["PHONE", /(?<!\d)(?:\+?880[ -]?|0)1[3-9][\d -]{8,10}\d(?!\d)|(?<!\d)\+\d{1,3}[ -]?\d[\d -]{7,12}\d(?!\d)/g, 0],
    ["ACCOUNT", /\b\d{9,16}\b/g, 0],
    ["NAME", /(?:my name is|I am|I'm|name:)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)/g, 1],
  ];
  function luhn(s) {
    const d = [...s].filter(c => /\d/.test(c)).map(Number);
    if (d.length < 13 || d.length > 19) return false;
    let t = 0;
    d.reverse().forEach((n, i) => { if (i % 2) { n *= 2; if (n > 9) n -= 9; } t += n; });
    return t % 10 === 0;
  }
  function findSpans(text) {
    const taken = [];
    for (const [kind, rx, grp] of PATTERNS) {
      rx.lastIndex = 0;
      for (const m of text.matchAll(rx)) {
        const val = grp ? m[grp] : m[0];
        const s = grp ? m.index + m[0].indexOf(val) : m.index, e = s + val.length;
        if (kind === "CARD" && !luhn(val)) continue;
        if (taken.some(t => s < t.end && e > t.start)) continue;
        taken.push({ start: s, end: e, kind, value: val });
      }
    }
    return taken.sort((a, b) => a.start - b.start);
  }
  async function mask(text, vault) {
    const spans = findSpans(text), table = {}, counters = {}, seen = new Map();
    let out = "", cur = 0;
    for (const sp of spans) {
      const key = sp.kind + "\u0000" + sp.value;
      if (!seen.has(key)) {
        counters[sp.kind] = (counters[sp.kind] || 0) + 1;
        const token = `⟦${sp.kind}_${counters[sp.kind]}⟧`;
        seen.set(key, token);
        table[token] = { kind: sp.kind, cipher: await vault.seal(sp.value, token) };
      }
      let { start, end } = sp;
      if (sp.kind === "SECRET") { start -= 2; end += 2; }
      out += text.slice(cur, start) + seen.get(key); cur = end;
    }
    return { masked: out + text.slice(cur), table, spans };
  }
  async function unmask(text, table, vault) {
    const events = [], segs = []; let cur = 0;
    for (const m of text.matchAll(/⟦\s*([A-Z]+)\s*\\?_\s*(\d+)\s*⟧/g)) {
      const tok = `⟦${m[1]}_${m[2]}⟧`;
      if (m.index > cur) segs.push({ t: text.slice(cur, m.index), s: "plain" });
      let val = tok, st;
      if (!table[tok]) { events.push({ token: tok, status: "unknown" }); st = "unknown"; }
      else {
        try { val = await vault.open(table[tok].cipher, tok); st = "opened"; events.push({ token: tok, status: "opened" }); }
        catch (e) { st = "sealed"; events.push({ token: tok, status: "sealed", reason: String(e.message || e) }); }
      }
      segs.push({ t: val, s: st, token: tok }); cur = m.index + m[0].length;
    }
    if (cur < text.length) segs.push({ t: text.slice(cur), s: "plain" });
    return { events, segs, plain: segs.map(s => s.t).join("") };
  }

  // Simulated model: it only ever sees the masked text. No network call is made.
  function simulatedModel(masked) {
    const toks = [...new Set(masked.match(/⟦[A-Z]+_\d+⟧/g) || [])];
    if (!toks.length) return "[SIMULATED reply: browser demo] I received your message. It had no protected values.";
    return `[SIMULATED reply: browser demo] I can see ${toks.length} protected reference(s): ${toks.join(", ")}. ` +
      `I can't read them, but I can refer to them: for example, please confirm that ${toks[0]} is correct before proceeding.`;
  }

  async function ask(vault, text) {
    const t0 = performance.now();
    let m;
    try { m = await mask(text, vault); }
    catch (e) { return { ok: false, error: String(e.message || e), stage: "seal" }; }
    const body = { system_instruction: { parts: [{ text: SYSTEM }] }, contents: [{ role: "user", parts: [{ text: m.masked }] }], generationConfig: { temperature: 0.3 } };
    const wire = JSON.stringify(body, null, 2);
    const plains = m.spans.map(s => s.value), shares = vault.shareHexes();
    const hits = plains.filter(p => p.length >= 3 && wire.includes(p)).length + shares.filter(s => wire.includes(s)).length;
    const check = { values_checked: plains.length, shares_checked: shares.length, leaks: hits };
    if (hits) return { ok: false, error: "Leak check failed: refusing to send.", stage: "leak", check };
    const reply = simulatedModel(m.masked);
    const u = await unmask(reply, m.table, vault);
    return { ok: true, mock: true, model: MODEL, endpoint: "(browser demo: this request is built and checked, but never sent anywhere)",
      original: text, masked: m.masked, wire, model_reply: reply, final: u.plain, final_segments: u.segs,
      spans: m.spans.map(sp => ({ start: sp.start - (sp.kind === "SECRET" ? 2 : 0), end: sp.end + (sp.kind === "SECRET" ? 2 : 0), kind: sp.kind })),
      vault: Object.entries(m.table).map(([token, v]) => ({ token, kind: v.kind, cipher: v.cipher })),
      events: u.events, check, ms: Math.round(performance.now() - t0) };
  }
  return { Vault, split, combine, gfMul, ask, findSpans, hex };
})();
if (typeof module !== "undefined") module.exports = VeilEngine;
