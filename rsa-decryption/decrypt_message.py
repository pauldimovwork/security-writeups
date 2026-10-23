#!/usr/bin/env python3
"""
Decrypt an RSA encrypted message.

Takes the private key and the encrypted message file, and prints the message.

How to run it:
    python decrypt_message.py private_key.pem emessage.etxt
"""

import sys
import base64
import binascii

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def load_ciphertext(path, block_size):
    """
    Open the message file and get the actual encrypted bytes out of it.

    The file could be saved three different ways: as plain bytes, or as text
    using hex or Base64. We try each one and see which gives us a sensible
    length. RSA always works in fixed size chunks (256 bytes for our key), so
    the right answer divides evenly by 256 and the wrong ones don't.
    """
    data = open(path, "rb").read()
    candidates = []

    # Remove any spaces and line breaks first, because text files like this
    # usually get wrapped onto multiple lines.
    text = b"".join(data.split())

    # Try reading it as hex. If the file isn't hex this throws, so we skip it.
    try:
        candidates.append(("hexadecimal", bytes.fromhex(text.decode("ascii"))))
    except (ValueError, UnicodeDecodeError):
        pass

    # Same thing for Base64.
    try:
        candidates.append(("Base64", base64.b64decode(text, validate=True)))
    except (binascii.Error, ValueError):
        pass

    # If neither worked, the file is probably already plain bytes.
    #
    # Note: we check hex and Base64 BEFORE this one on purpose. A hex file is
    # double the length of the real data, so 256 bytes of hex is 512
    # characters. 512 divides evenly by 256 too, so if we checked plain bytes
    # first a hex file would pass the test for the wrong reason. Found this
    # out the hard way while testing.
    candidates.append(("raw binary", data))

    # Go through them in order and take the first one with a valid length.
    for name, blob in candidates:
        if blob and len(blob) % block_size == 0:
            print(f"[*] Ciphertext encoding detected: {name}")
            print(f"[*] Ciphertext length: {len(blob)} bytes "
                  f"({len(blob) // block_size} block(s) of {block_size})")
            return blob

    # Nothing had a valid length, so the file might be damaged. Try the plain
    # bytes anyway and let the user see what happens.
    print("[!] Could not confirm an encoding; trying the raw file bytes.")
    return data


def looks_like_text(data):
    """
    Check if what we got back is a real message or just junk.

    We need this because trying the wrong padding doesn't always give an
    error. PKCS#1 v1.5 in particular just hands back random looking bytes and
    doesn't complain. That's on purpose for security reasons, but it means we
    can't tell if it worked by checking for errors. So we check the result
    instead: a real message reads as normal text, junk doesn't.
    """
    if not data:
        return False

    # If it isn't valid text at all, it's junk.
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False

    # Count the normal readable characters. A real message is basically all
    # readable. Junk has lots of weird control characters mixed in.
    printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text)
    return printable / len(text) > 0.95


def decrypt_block(private_key, block):
    """
    Decrypt one 256 byte chunk by trying each type of padding.

    Returns the name of the padding that worked and the decrypted bytes.
    """
    schemes = [
        ("OAEP (SHA-256)", padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None)),
        ("OAEP (SHA-1)", padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None)),
        ("PKCS#1 v1.5", padding.PKCS1v15()),
    ]

    # Try each padding type. Don't stop at the first one that doesn't error,
    # because that isn't proof it worked (see looks_like_text above). Keep
    # going until we get something readable.
    fallback = None
    for name, scheme in schemes:
        try:
            result = private_key.decrypt(block, scheme)
        except Exception:
            continue
        if looks_like_text(result):
            return name, result
        # Hang onto the first result in case nothing readable turns up, so we
        # have something to show at the end.
        if fallback is None:
            fallback = (name, result)

    # None of the normal padding worked, so maybe there's no padding at all.
    # Without padding, RSA is just one math step: take the chunk as a big
    # number, raise it to the power d, divide by n and keep the remainder.
    # The library won't do this for us because it's not secure, so we do the
    # math ourselves.
    numbers = private_key.private_numbers()
    d, n = numbers.d, numbers.public_numbers.n
    m = pow(int.from_bytes(block, "big"), d, n)
    plain = m.to_bytes((m.bit_length() + 7) // 8, "big")
    if looks_like_text(plain):
        return "none (textbook RSA)", plain

    # Still nothing readable. Show the best we got so the user can look at it.
    print("[!] No padding scheme produced clearly readable text. "
          "Showing the closest attempt -- inspect the output carefully.")
    return fallback if fallback else ("none (textbook RSA)", plain)


def main():
    # Expect two arguments: the key file and the message file.
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)

    key_path, message_path = sys.argv[1], sys.argv[2]

    # Load the private key. password=None because this key isn't locked.
    private_key = serialization.load_pem_private_key(
        open(key_path, "rb").read(), password=None)

    # Our key is 2048 bits, which is 256 bytes. That's the chunk size RSA
    # works in, and we need it in a few places below.
    block_size = private_key.key_size // 8
    print(f"[*] Loaded a {private_key.key_size}-bit RSA private key")

    ciphertext = load_ciphertext(message_path, block_size)

    # Go through the message one chunk at a time and stick the results
    # together. A short message is just one chunk, but a longer one would
    # have been split up before it was encrypted.
    plaintext = b""
    scheme_used = None
    for offset in range(0, len(ciphertext), block_size):
        scheme_used, chunk = decrypt_block(
            private_key, ciphertext[offset:offset + block_size])
        plaintext += chunk

    print(f"[*] Padding scheme detected: {scheme_used}")
    print("\n----- DECRYPTED MESSAGE -----")
    print(plaintext.decode("utf-8", errors="replace"))
    print("----- END OF MESSAGE -----")


if __name__ == "__main__":
    main()
