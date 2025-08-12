# Decryptor for Snake Keylogger
#!/usr/bin/env python3
# DES/ECB(Base64) decryptor, supports multi decode and changing key:
# key bytes = MD5(ASCII(passphrase))[:8], padding = PKCS7, plaintext decoded as ASCII.
# Usage:
#   python des_decrypt.py "BASE64_1" "BASE64_2"
#   python des_decrypt.py -k "your-passphrase" "BASE64_1"

import argparse, base64, hashlib, sys
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad

DEFAULT_PASS = (
    "BsrOkyiChvpfhAkipZAxnnChkMGkLnAiZhGMyrnJfULiDGkfTkrTELinhfkLkJrkDExMvkEUCxUkUGr"
)

def des_key_from_pass_ascii(passphrase: str) -> bytes:
    # Matches: MD5CryptoServiceProvider over ASCII, first 8 bytes
    return hashlib.md5(passphrase.encode("ascii", errors="strict")).digest()[:8]

def decrypt_des_base64(b64_s: str, passphrase: str) -> str:
    key = des_key_from_pass_ascii(passphrase)
    ct  = base64.b64decode(b64_s.strip())
    pt  = DES.new(key, DES.MODE_ECB).decrypt(ct)
    try:
        pt = unpad(pt, 8, style="pkcs7")
    except ValueError:
        pass  # keep raw if no/invalid padding
    # C# used Encoding.ASCII.GetString(...)
    return pt.decode("ascii", errors="ignore")

def main():
    ap = argparse.ArgumentParser(description="DES/ECB(Base64) decrypt (MD5(ASCII(pass))[:8] key).")
    ap.add_argument("strings", nargs="*", help="Base64 ciphertext(s) to decrypt")
    ap.add_argument("-k", "--key", default=DEFAULT_PASS,
                    help="ASCII passphrase (default: built-in long string)")
    args = ap.parse_args()

    items = args.strings or [line.strip() for line in sys.stdin if line.strip()]
    if not items:
        print("No input strings provided.", file=sys.stderr)
        sys.exit(2)

    for s in items:
        try:
            print(decrypt_des_base64(s, args.key))
        except Exception as e:
            print(f"[!] failed: {s} ({e})", file=sys.stderr)

if __name__ == "__main__":
    main()
