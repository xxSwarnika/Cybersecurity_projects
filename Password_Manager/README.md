Secure Password Manager

A command-line password manager written in Python. It stores all your logins in a single vault file. The vault is encrypted with AES-256-GCM and unlocked by a master password that is never saved anywhere.

Features are:
Add, view, search, edit and delete entries (name, username/email, password, notes)
Generate strong random passwords
Change the master password, which re-encrypts the vault with a new key
Passwords stay hidden while you type them and are only shown when you ask
Locks after three wrong master password attempts
Security design
What How
Key derivation scrypt (N=2¹⁷, r=8, p=1) with a random 16-byte salt. This makes each guess of the master password slow and memory-hungry, which protects against brute-force attacks.
Encryption AES-256-GCM, which encrypts the data and also detects any tampering.
Nonces A fresh random nonce is used every time the vault is saved.
Header protection The salt and scrypt settings are authenticated together with the data, so they can't be changed without detection.
Password generation Uses Python's secrets module, which is designed for cryptographic randomness.
File safety The vault is written atomically, so a crash can't leave a half-written file. It gets owner-only permissions (600).

The master password is never stored. If you forget it, your data cannot be recovered.

Requirements
Python 3.10 or newer
The cryptography package
bash
pip install cryptography
Usage
bash
python password_manager.py

The first time you run the program, it creates a new vault called vault.enc and asks you to choose a master password. The master password must be at least 12 characters long and mix at least three of: lowercase letters, uppercase letters, digits and symbols.

To use a different vault file:

bash
python password_manager.py --vault my_passwords.vault

After you unlock the vault, you get this menu:

1. Add an entry
2. Show an entry
3. List all entries
4. Search
5. Edit an entry
6. Delete an entry
7. Generate a password
8. Change master password
9. Lock and quit
   Vault file format

The vault is a JSON file with three parts:

json

{
"header": { "version": 1, "kdf": "scrypt", "salt": "...", "n": 131072, "r": 8, "p": 1 },
"nonce": "...",
"ciphertext": "..."
}

All entries are inside ciphertext. Nothing readable about your accounts is stored in plain text.

Limitations

This is a learning project and has not been professionally audited. For real-world use, choose an established password manager such as Bitwarden or KeePassXC. Known limitations:

Revealed passwords are printed to the terminal, so they may remain in your scrollback history.
Python can't reliably wipe secrets from memory after use.
There is no clipboard support and no sync between devices.
