# RSA Decryption with Automatic Encoding and Padding Detection

**Applied cryptography project · Python · September 2026**

> Given an RSA private key and an encrypted message, I built a Python tool that
> decrypts the message **without being told how the file was encoded or which
> padding scheme was used**. The tool works both out on its own and validates
> that the result is real plaintext. The original dataset is not included.

---

## Contents

- [The problem](#the-problem)
- [Tools & skills](#tools--skills)
- [How the solution works](#how-the-solution-works)
- [Running it](#running-it)
- [Two bugs found by testing](#two-bugs-found-by-testing)
- [Result](#result)
- [What I learned](#what-i-learned)
- [References](#references)

---

## The problem

RSA decryption is one line of math: treat the ciphertext as a number, raise it to
the private exponent `d`, and take the remainder modulo `n`. In practice, two
things get in the way:

1. **Encoding.** Ciphertext is raw bytes, which are often converted to hex or
   Base64 so they survive being sent as text. The file didn't say which.
2. **Padding.** Real-world RSA wraps the message in padding before encrypting it.
   There are several standard schemes, and the file didn't say which one was used.

The goal was to build a tool that handles both automatically and can prove its
answer is correct.

---

## Tools & skills

| Area | Used in this project |
|---|---|
| **Language** | Python 3 |
| **Library** | `cryptography` (PEM key loading, RSA, OAEP and PKCS#1 v1.5 padding) |
| **Cryptography** | RSA key structure (`n`, `d`, `e`), modular exponentiation, padding schemes, padding-oracle attacks |
| **Encoding** | Raw binary, hexadecimal, Base64 |
| **Testing** | Round-trip testing: encrypt known messages with the public key, confirm the tool recovers them |

---

## How the solution works

Only the private key is needed. The public key can encrypt but not decrypt, so it
is used only for testing.

1. **Load the private key.** The PEM file holds the modulus `n` and the private
   exponent `d`, which together are the ability to decrypt. The key is 2048 bits,
   so RSA works in fixed 256-byte blocks.
2. **Detect the file encoding.** The tool tries hex, then Base64, then raw binary,
   and keeps whichever decoding produces a length that is an exact multiple of
   256 bytes. Real ciphertext from a 2048-bit key is always a whole number of
   blocks, so a wrong guess leaves a remainder.
3. **Split into blocks.** A short message is one block; a longer one is decrypted
   block by block and reassembled in order.
4. **Reverse the encryption.** For each block: `plaintext = ciphertext^d mod n`.
5. **Remove the padding.** The tool tries OAEP with SHA-256, OAEP with SHA-1,
   PKCS#1 v1.5, and finally no padding ("textbook" RSA).
6. **Validate the output.** Each candidate is checked for valid UTF-8 and a high
   proportion of printable characters. The scheme that produces readable text is
   the one that was used.

---

## Running it

The code is in [`decrypt_message.py`](decrypt_message.py). It needs Python 3 and the
`cryptography` library:

```
pip install cryptography
python decrypt_message.py private_key.pem emessage.etxt
```

Example output on a test message:

```
[*] Loaded a 2048-bit RSA private key
[*] Ciphertext encoding detected: raw binary
[*] Ciphertext length: 256 bytes (1 block(s) of 256)
[*] Padding scheme detected: OAEP (SHA-1)

----- DECRYPTED MESSAGE -----
Round-trip test message.
----- END OF MESSAGE -----
```

The script was tested by encrypting known messages with the public key in every
combination it handles (raw, hex, and Base64 files; OAEP SHA-256, OAEP SHA-1, and
PKCS#1 v1.5 padding) and confirming each one decrypted correctly.

---

## Two bugs found by testing

Both of these were caught by round-trip testing, not by reasoning ahead. They're
the most valuable part of the project.

### 1. Hex has to be checked before raw binary

A hex file is exactly twice as long as the bytes it represents. One 256-byte block
written as hex is 512 characters, and 512 also divides evenly by 256. So if the
tool checked "raw binary" first, a hex file would pass the length test for the
wrong reason and be misread as two blocks of garbage. Checking hex and Base64 first
fixed it.

### 2. "No error" doesn't mean "correct padding"

My first version picked the padding scheme by taking whichever one didn't raise an
error. Testing showed this gave wrong answers with no warning.

The reason: **PKCS#1 v1.5 unpadding deliberately returns meaningless bytes instead
of raising an error on bad input.** That's intentional. If the library reported
"bad padding" differently from "bad message," an attacker could send modified
ciphertexts and use those different responses to recover the plaintext without
ever having the key. That's a **padding-oracle attack** (Bleichenbacher's attack).

The fix was to stop trusting exceptions and validate the *output* instead, which
is why step 6 exists.

---

## Result

The tool decrypted the assigned message:

> Thank you for rescuing me from that prision

("Prison" is misspelled in the original message, not a decryption error.)

| Property | Value |
|---|---|
| Key size | 2048-bit RSA |
| Public exponent | 65537 |
| Ciphertext size | 256 bytes (one RSA block) |
| Ciphertext encoding | Raw binary |
| Padding scheme | OAEP with SHA-1 |

The result is confirmed rather than guessed: OAEP includes a built-in integrity
check that fails outright on a wrong key or damaged input. The message both
unpadded cleanly and produced readable English, which together rule out
coincidence.

---

## What I learned

- **Real-world crypto is mostly bookkeeping.** The RSA math is one line. Encoding,
  block sizes, and padding are where things actually go wrong.
- **Silent failure is a security feature.** A crypto library refusing to tell you
  *why* decryption failed isn't a bug; it's what stops padding-oracle attacks.
- **Test with known answers.** Encrypting my own messages and checking that the tool
  recovered them caught both bugs before they could produce a wrong answer.
- **Textbook RSA is insecure.** Without padding, the same message always encrypts
  the same way and the ciphertext can be manipulated. That's why modern systems use
  OAEP.

---

## References

- [`cryptography` library documentation: RSA](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/)
- [RFC 8017: PKCS #1 v2.2 (RSA Cryptography Specifications)](https://www.rfc-editor.org/rfc/rfc8017)
