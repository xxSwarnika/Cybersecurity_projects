#!/usr/bin/env python3
"""Secure password manager.

All entries are stored in one encrypted vault file. The vault is locked with a
master password that is never saved anywhere.

Security design:
  - Key derivation: scrypt (N=2^17, r=8, p=1) with a random 16-byte salt,
    which makes guessing the master password slow and memory-hungry.
  - Encryption: AES-256-GCM, which both encrypts and detects tampering.
    A fresh random nonce is used every time the vault is saved.
  - The vault header (salt and KDF settings) is authenticated too, so it
    cannot be modified without detection.
  - Generated passwords come from the `secrets` module (cryptographically secure).
  - The vault file is written atomically with owner-only permissions (600).

Requires:  pip install cryptography

Usage:
    python password_manager.py            # open (or create) the vault
    python password_manager.py --vault my.vault
"""

import argparse
import base64
import getpass
import json
import os
import secrets
import string
import sys
import tempfile

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ImportError:
    sys.exit("This app needs the 'cryptography' package. Install it with: pip install cryptography")

DEFAULT_VAULT = "vault.enc"
VAULT_VERSION = 1
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**17, 8, 1
MIN_MASTER_LENGTH = 12


class VaultError(Exception):
    pass


# ---------------------------------------------------------------- crypto ---

def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def derive_key(master: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
    return kdf.derive(master.encode("utf-8"))


def header_bytes(header: dict) -> bytes:
    """Canonical form of the header, used as authenticated data."""
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")


class Vault:
    def __init__(self, path: str, key: bytes, header: dict, entries: dict):
        self.path = path
        self._key = key
        self.header = header
        self.entries = entries  # name -> {"username": ..., "password": ..., "notes": ...}

    # ---- creating and opening ----

    @classmethod
    def create(cls, path: str, master: str) -> "Vault":
        header = {
            "version": VAULT_VERSION,
            "kdf": "scrypt",
            "salt": b64e(os.urandom(16)),
            "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P,
        }
        key = derive_key(master, b64d(header["salt"]), SCRYPT_N, SCRYPT_R, SCRYPT_P)
        vault = cls(path, key, header, {})
        vault.save()
        return vault

    @classmethod
    def open(cls, path: str, master: str) -> "Vault":
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            header = data["header"]
            nonce = b64d(data["nonce"])
            ciphertext = b64d(data["ciphertext"])
        except (OSError, ValueError, KeyError) as exc:
            raise VaultError(f"Could not read the vault file: {exc}") from exc

        if header.get("version") != VAULT_VERSION or header.get("kdf") != "scrypt":
            raise VaultError("Unsupported vault format.")

        key = derive_key(master, b64d(header["salt"]), header["n"], header["r"], header["p"])
        try:
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, header_bytes(header))
        except InvalidTag:
            raise VaultError("Wrong master password, or the vault file has been tampered with.")
        return cls(path, key, header, json.loads(plaintext.decode("utf-8")))

    # ---- saving ----

    def save(self) -> None:
        nonce = os.urandom(12)
        plaintext = json.dumps(self.entries).encode("utf-8")
        ciphertext = AESGCM(self._key).encrypt(nonce, plaintext, header_bytes(self.header))
        blob = {"header": self.header, "nonce": b64e(nonce), "ciphertext": b64e(ciphertext)}

        # Write to a temporary file first, then swap it in, so a crash
        # halfway through can never leave a half-written vault.
        directory = os.path.dirname(os.path.abspath(self.path))
        fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".vault-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(blob, f)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, self.path)
        except BaseException:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

    def change_master(self, new_master: str) -> None:
        """Re-encrypt everything with a new master password and a new salt."""
        self.header["salt"] = b64e(os.urandom(16))
        self._key = derive_key(new_master, b64d(self.header["salt"]),
                               self.header["n"], self.header["r"], self.header["p"])
        self.save()


# ------------------------------------------------------ password tools ---

def generate_password(length: int = 20, symbols: bool = True) -> str:
    """Random password with at least one lowercase, uppercase, digit (and symbol)."""
    pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if symbols:
        pools.append("!@#$%^&*()-_=+[]{};:,.?")
    if length < len(pools):
        raise ValueError(f"Length must be at least {len(pools)}.")
    alphabet = "".join(pools)
    chars = [secrets.choice(pool) for pool in pools]
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def master_password_problems(pw: str) -> list[str]:
    problems = []
    if len(pw) < MIN_MASTER_LENGTH:
        problems.append(f"be at least {MIN_MASTER_LENGTH} characters long")
    kinds = sum([any(c.islower() for c in pw), any(c.isupper() for c in pw),
                 any(c.isdigit() for c in pw), any(not c.isalnum() for c in pw)])
    if kinds < 3:
        problems.append("mix at least three of: lowercase, uppercase, digits, symbols")
    return problems


# ------------------------------------------------------------ menu UI ---

def ask(prompt: str, allow_empty: bool = False) -> str:
    while True:
        value = input(prompt).strip()
        if value or allow_empty:
            return value
        print("This can't be empty.")


def ask_yes_no(prompt: str) -> bool:
    return input(f"{prompt} [y/N]: ").strip().lower() in ("y", "yes")


def ask_new_master() -> str:
    while True:
        pw = getpass.getpass("New master password: ")
        problems = master_password_problems(pw)
        if problems:
            print("The master password must " + " and ".join(problems) + ".")
            continue
        if getpass.getpass("Repeat master password: ") != pw:
            print("The passwords didn't match. Try again.")
            continue
        return pw


def ask_entry_password() -> str:
    if ask_yes_no("Generate a strong password?"):
        length_raw = input("Length [20]: ").strip()
        length = int(length_raw) if length_raw.isdigit() else 20
        pw = generate_password(max(length, 8))
        print("Password generated.")
        return pw
    while True:
        pw = getpass.getpass("Password (hidden): ")
        if pw:
            return pw
        print("The password can't be empty.")


def find_entry(vault: Vault, name: str) -> str | None:
    """Case-insensitive lookup; returns the stored name or None."""
    for stored in vault.entries:
        if stored.lower() == name.lower():
            return stored
    return None


def menu(vault: Vault) -> None:
    actions = {
        "1": "Add an entry",
        "2": "Show an entry",
        "3": "List all entries",
        "4": "Search",
        "5": "Edit an entry",
        "6": "Delete an entry",
        "7": "Generate a password",
        "8": "Change master password",
        "9": "Lock and quit",
    }
    while True:
        print()
        for key, label in actions.items():
            print(f"{key}) {label}")
        choice = input("\nChoose an option (1-9): ").strip()

        if choice == "1":
            name = ask("Name (e.g. GitHub): ")
            if find_entry(vault, name):
                print(f"'{name}' already exists. Use 'Edit' to change it.")
                continue
            vault.entries[name] = {
                "username": ask("Username / email: ", allow_empty=True),
                "password": ask_entry_password(),
                "notes": ask("Notes (optional): ", allow_empty=True),
            }
            vault.save()
            print(f"Saved '{name}'.")

        elif choice == "2":
            name = find_entry(vault, ask("Name: "))
            if not name:
                print("No entry with that name.")
                continue
            e = vault.entries[name]
            print(f"\n{name}\n  Username: {e['username'] or '-'}")
            if e["notes"]:
                print(f"  Notes:    {e['notes']}")
            if ask_yes_no("Reveal the password on screen?"):
                print(f"  Password: {e['password']}")

        elif choice == "3":
            if not vault.entries:
                print("The vault is empty.")
            for name in sorted(vault.entries, key=str.lower):
                print(f"  {name}  ({vault.entries[name]['username'] or '-'})")

        elif choice == "4":
            term = ask("Search for: ").lower()
            hits = [n for n, e in vault.entries.items()
                    if term in n.lower() or term in e["username"].lower()]
            print("\n".join(f"  {n}" for n in sorted(hits)) if hits else "No matches.")

        elif choice == "5":
            name = find_entry(vault, ask("Name: "))
            if not name:
                print("No entry with that name.")
                continue
            e = vault.entries[name]
            print("Press Enter to keep the current value.")
            e["username"] = ask(f"Username [{e['username']}]: ", allow_empty=True) or e["username"]
            if ask_yes_no("Change the password?"):
                e["password"] = ask_entry_password()
            e["notes"] = ask(f"Notes [{e['notes']}]: ", allow_empty=True) or e["notes"]
            vault.save()
            print(f"Updated '{name}'.")

        elif choice == "6":
            name = find_entry(vault, ask("Name: "))
            if not name:
                print("No entry with that name.")
            elif ask_yes_no(f"Really delete '{name}'?"):
                del vault.entries[name]
                vault.save()
                print(f"Deleted '{name}'.")

        elif choice == "7":
            length_raw = input("Length [20]: ").strip()
            length = int(length_raw) if length_raw.isdigit() else 20
            print(generate_password(max(length, 8)))

        elif choice == "8":
            current = getpass.getpass("Current master password: ")
            try:
                Vault.open(vault.path, current)
            except VaultError:
                print("That's not the current master password.")
                continue
            print("Deriving new key, this takes a moment...")
            vault.change_master(ask_new_master())
            print("Master password changed.")

        elif choice == "9":
            print("Vault locked. Goodbye!")
            return
        else:
            print("Please choose a number from 1 to 9.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Secure password manager.")
    parser.add_argument("--vault", default=DEFAULT_VAULT,
                        help=f"path to the vault file (default: {DEFAULT_VAULT})")
    args = parser.parse_args()

    print("=" * 40)
    print("  Secure Password Manager")
    print("=" * 40)

    try:
        if not os.path.exists(args.vault):
            print(f"No vault found at '{args.vault}'. Let's create one.")
            print("Remember your master password: it can NOT be recovered.\n")
            master = ask_new_master()
            print("Creating vault...")
            vault = Vault.create(args.vault, master)
        else:
            for attempt in range(3):
                master = getpass.getpass("Master password: ")
                print("Unlocking...")
                try:
                    vault = Vault.open(args.vault, master)
                    break
                except VaultError as exc:
                    print(exc)
            else:
                sys.exit("Too many failed attempts.")
        del master
        print(f"Vault unlocked ({len(vault.entries)} entries).")
        menu(vault)
    except (KeyboardInterrupt, EOFError):
        print("\nVault locked. Goodbye!")


if __name__ == "__main__":
    main()
