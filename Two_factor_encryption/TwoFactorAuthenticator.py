#!/usr/bin/env python3
"""Two-factor authenticator (TOTP, RFC 6238) - works like Google Authenticator.

Uses only the Python standard library. Codes are compatible with Google
Authenticator, Microsoft Authenticator, Authy, 1Password and similar apps.

Commands:
    python totp_authenticator.py add "GitHub"            # create a new secret
    python totp_authenticator.py add "Gmail" --secret JBSWY3DPEHPK3PXP
    python totp_authenticator.py list                     # codes for all accounts
    python totp_authenticator.py watch                    # live codes with countdown
    python totp_authenticator.py code "GitHub"            # one code
    python totp_authenticator.py verify "GitHub" 123456   # check a code
    python totp_authenticator.py uri "GitHub"             # otpauth:// link for an app
    python totp_authenticator.py remove "GitHub"
    python totp_authenticator.py test                     # check against RFC 6238 vectors
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import sys
import time
from urllib.parse import quote

STORE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "authenticator.json")
PERIOD = 30
DIGITS = 6
ALGORITHM = "SHA1"  # what nearly all authenticator apps expect


# ---------------------------------------------------------------- TOTP core --
def normalize_secret(secret: str) -> str:
    """Upper-case, strip spaces/dashes and validate base32."""
    cleaned = secret.replace(" ", "").replace("-", "").upper()
    padded = cleaned + "=" * (-len(cleaned) % 8)
    try:
        base64.b32decode(padded)
    except Exception:
        raise ValueError("That is not a valid base32 secret (use letters A-Z and digits 2-7).")
    return cleaned


def generate_secret(num_bytes: int = 20) -> str:
    """Random base32 secret (20 bytes = 160 bits, the recommended size)."""
    return base64.b32encode(secrets.token_bytes(num_bytes)).decode().rstrip("=")


def hotp(secret: str, counter: int, digits: int = DIGITS, algorithm: str = ALGORITHM) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, getattr(hashlib, algorithm.lower())).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp(secret: str, at: float | None = None, period: int = PERIOD,
         digits: int = DIGITS, algorithm: str = ALGORITHM) -> str:
    at = time.time() if at is None else at
    return hotp(secret, int(at // period), digits, algorithm)


def seconds_left(period: int = PERIOD) -> int:
    return period - int(time.time() % period)


def verify(secret: str, code: str, window: int = 1, period: int = PERIOD) -> bool:
    """Accept the current code and `window` steps either side to allow for clock drift."""
    code = code.strip().replace(" ", "")
    if not (code.isdigit() and len(code) == DIGITS):
        return False
    counter = int(time.time() // period)
    ok = False
    for step in range(-window, window + 1):  # check every step so timing stays constant
        if hmac.compare_digest(hotp(secret, counter + step), code):
            ok = True
    return ok


def otpauth_uri(account: str, secret: str, issuer: str) -> str:
    label = quote(f"{issuer}:{account}") if issuer else quote(account)
    uri = f"otpauth://totp/{label}?secret={secret}&algorithm={ALGORITHM}&digits={DIGITS}&period={PERIOD}"
    if issuer:
        uri += f"&issuer={quote(issuer)}"
    return uri


# ------------------------------------------------------------------ storage --
def load_store() -> dict:
    if not os.path.exists(STORE):
        return {}
    try:
        with open(STORE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        sys.exit(f"Could not read {STORE}. Fix or delete the file and try again.")


def save_store(data: dict) -> None:
    with open(STORE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    try:
        os.chmod(STORE, 0o600)  # owner-only; the file holds your secrets
    except OSError:
        pass


def find_account(data: dict, name: str) -> str:
    for key in data:
        if key.lower() == name.lower():
            return key
    sys.exit(f"No account called '{name}'. Run 'list' to see your accounts.")


def group(code: str) -> str:
    half = len(code) // 2
    return f"{code[:half]} {code[half:]}"


# ----------------------------------------------------------------- commands --
def cmd_add(args) -> None:
    data = load_store()
    if any(k.lower() == args.name.lower() for k in data):
        sys.exit(f"'{args.name}' already exists. Remove it first to replace it.")
    try:
        secret = normalize_secret(args.secret) if args.secret else generate_secret()
    except ValueError as e:
        sys.exit(str(e))
    data[args.name] = {"secret": secret, "issuer": args.issuer or args.name}
    save_store(data)

    print(f"Added '{args.name}'.")
    if not args.secret:
        print(f"\nSecret key (type this into your service's 2FA setup):\n  {secret}")
        print(f"\nOr paste this link into an authenticator app:\n  {otpauth_uri(args.name, secret, args.issuer or args.name)}")
    print(f"\nCurrent code: {group(totp(secret))}  ({seconds_left()}s left)")


def cmd_list(_args) -> None:
    data = load_store()
    if not data:
        print("No accounts yet. Add one with:  python totp_authenticator.py add \"Name\"")
        return
    left = seconds_left()
    width = max(len(n) for n in data)
    for name, info in data.items():
        print(f"{name:<{width}}  {group(totp(info['secret']))}")
    print(f"\nCodes change in {left}s.")


def cmd_watch(_args) -> None:
    data = load_store()
    if not data:
        sys.exit("No accounts yet. Add one first.")
    width = max(len(n) for n in data)
    print("Live codes (Ctrl+C to stop)\n")
    try:
        while True:
            left = seconds_left()
            bar = "#" * (left * 20 // PERIOD)
            lines = [f"{n:<{width}}  {group(totp(i['secret']))}" for n, i in data.items()]
            lines.append(f"\n[{bar:<20}] {left:>2}s")
            sys.stdout.write("\033[F" * (len(lines) + 1) if getattr(cmd_watch, "drawn", False) else "")
            sys.stdout.write("\n".join(lines) + "\n")
            sys.stdout.flush()
            cmd_watch.drawn = True
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopped.")


def cmd_code(args) -> None:
    data = load_store()
    name = find_account(data, args.name)
    print(f"{group(totp(data[name]['secret']))}  ({seconds_left()}s left)")


def cmd_verify(args) -> None:
    data = load_store()
    name = find_account(data, args.name)
    if verify(data[name]["secret"], args.code):
        print("Code is valid.")
    else:
        print("Code is NOT valid.")
        sys.exit(1)


def cmd_uri(args) -> None:
    data = load_store()
    name = find_account(data, args.name)
    print(otpauth_uri(name, data[name]["secret"], data[name].get("issuer", name)))


def cmd_remove(args) -> None:
    data = load_store()
    name = find_account(data, args.name)
    del data[name]
    save_store(data)
    print(f"Removed '{name}'.")


def cmd_test(_args) -> None:
    """RFC 6238 test vectors (SHA-1, secret '12345678901234567890', 8 digits)."""
    secret = base64.b32encode(b"12345678901234567890").decode().rstrip("=")
    vectors = {59: "94287082", 1111111109: "07081804", 1111111111: "14050471",
               1234567890: "89005924", 2000000000: "69279037", 20000000000: "65353130"}
    failed = 0
    for t, expected in vectors.items():
        got = totp(secret, at=t, digits=8)
        status = "ok" if got == expected else "FAIL"
        failed += got != expected
        print(f"time={t:<12} expected={expected} got={got}  {status}")
    print("\nAll tests passed." if not failed else f"\n{failed} test(s) failed.")
    sys.exit(1 if failed else 0)


def main() -> None:
    parser = argparse.ArgumentParser(description="Two-factor authenticator (TOTP).")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("add", help="add an account")
    p.add_argument("name")
    p.add_argument("--secret", help="existing base32 secret from a service (omit to generate one)")
    p.add_argument("--issuer", help="service name shown in apps (default: the account name)")
    p.set_defaults(func=cmd_add)

    sub.add_parser("list", help="show codes for all accounts").set_defaults(func=cmd_list)
    sub.add_parser("watch", help="live codes with a countdown").set_defaults(func=cmd_watch)

    for name, fn, helptext in (("code", cmd_code, "show one code"),
                               ("uri", cmd_uri, "print the otpauth:// link"),
                               ("remove", cmd_remove, "delete an account")):
        p = sub.add_parser(name, help=helptext)
        p.add_argument("name")
        p.set_defaults(func=fn)

    p = sub.add_parser("verify", help="check a code the user typed")
    p.add_argument("name")
    p.add_argument("code")
    p.set_defaults(func=cmd_verify)

    sub.add_parser("test", help="run the RFC 6238 self-test").set_defaults(func=cmd_test)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()