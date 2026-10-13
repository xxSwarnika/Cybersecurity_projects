#!/usr/bin/env python3
"""Caesar cipher text encryption.

Run with no arguments for an interactive menu, or use the command line:

    python caesar_cipher.py encrypt "Hello, World!" --shift 3
    python caesar_cipher.py decrypt "Khoor, Zruog!" --shift 3
    python caesar_cipher.py brute "Khoor, Zruog!"
"""

import argparse
import string
import sys

ALPHABET_SIZE = 26


def shift_text(text: str, shift: int) -> str:
    """Shift every letter by `shift` places. Case is kept, other characters are left alone."""
    shift %= ALPHABET_SIZE
    result = []
    for ch in text:
        if ch in string.ascii_lowercase:
            result.append(chr((ord(ch) - ord("a") + shift) % ALPHABET_SIZE + ord("a")))
        elif ch in string.ascii_uppercase:
            result.append(chr((ord(ch) - ord("A") + shift) % ALPHABET_SIZE + ord("A")))
        else:
            result.append(ch)
    return "".join(result)


def encrypt(text: str, shift: int) -> str:
    return shift_text(text, shift)


def decrypt(text: str, shift: int) -> str:
    return shift_text(text, -shift)


def brute_force(text: str) -> list[tuple[int, str]]:
    """Try every possible shift (1-25) and return (shift, decrypted_text) pairs."""
    return [(s, decrypt(text, s)) for s in range(1, ALPHABET_SIZE)]


def ask_shift(default: int = 3) -> int:
    while True:
        raw = input(f"Shift amount (any whole number) [{default}]: ").strip()
        if not raw:
            return default
        try:
            return int(raw)
        except ValueError:
            print("Please enter a whole number, for example 3 or -5.")


def ask_text(prompt: str) -> str:
    while True:
        text = input(prompt)
        if text.strip():
            return text
        print("The text can't be empty.")


def interactive_menu() -> None:
    print("=" * 40)
    print("  Caesar Cipher - Text Encryption App")
    print("=" * 40)
    while True:
        print("\n1) Encrypt a message")
        print("2) Decrypt a message")
        print("3) Break a message (try all shifts)")
        print("4) Quit")
        choice = input("\nChoose an option (1-4): ").strip()

        if choice == "1":
            text = ask_text("Message to encrypt: ")
            shift = ask_shift()
            print(f"\nEncrypted: {encrypt(text, shift)}")
        elif choice == "2":
            text = ask_text("Message to decrypt: ")
            shift = ask_shift()
            print(f"\nDecrypted: {decrypt(text, shift)}")
        elif choice == "3":
            text = ask_text("Encrypted message: ")
            print()
            for s, candidate in brute_force(text):
                print(f"Shift {s:>2}: {candidate}")
        elif choice == "4":
            print("Goodbye!")
            return
        else:
            print("Please choose 1, 2, 3 or 4.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Caesar cipher text encryption app.")
    sub = parser.add_subparsers(dest="command")

    for name, helptext in (("encrypt", "Encrypt a message"), ("decrypt", "Decrypt a message")):
        p = sub.add_parser(name, help=helptext)
        p.add_argument("text", help="the message (use quotes if it has spaces)")
        p.add_argument("-s", "--shift", type=int, default=3, help="shift amount (default: 3)")

    b = sub.add_parser("brute", help="try all 25 shifts on an encrypted message")
    b.add_argument("text", help="the encrypted message")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        try:
            interactive_menu()
        except (KeyboardInterrupt, EOFError):
            print("\nGoodbye!")
        return

    if args.command == "encrypt":
        print(encrypt(args.text, args.shift))
    elif args.command == "decrypt":
        print(decrypt(args.text, args.shift))
    elif args.command == "brute":
        for s, candidate in brute_force(args.text):
            print(f"Shift {s:>2}: {candidate}")


if __name__ == "__main__":
    sys.exit(main())