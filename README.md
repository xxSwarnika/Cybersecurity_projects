Cybersecurity Projects

A collection of ten small security tools I built while studying Informatics (Cybersecurity) at the University of Bergen. They cover encryption, password security, authentication and network analysis. The browser tools run entirely on your own device. The Python tools only need Python 3, and most use just the standard library.

Projects
1. Caesar Cipher
Encryption_Ceasar_Cipher:

A Python app that encrypts and decrypts text with the classic Caesar cipher. It can also break an encrypted message by trying all 25 possible shifts.

bash
python Ceasar_Cipher.py                             # interactive menu
python Ceasar_Cipher.py encrypt "Hello" --shift 3
python Ceasar_Cipher.py brute "Khoor"

2. Password Manager
 Password_Manager

A command-line password manager that stores your logins in a vault encrypted with AES-256-GCM. The vault is unlocked by a master password that is never saved, and the key is derived with scrypt to slow down guessing attacks. Install the cryptography package, then run the script and follow the menu.

bash
pip install cryptography
python password_manager.py

3. Password Generator
 Password_maker:

A web page that generates strong random passwords using the browser's secure random number generator. You choose the length and which character types to include, and copy the result with one click. Open Password Generator.html in any browser.

4. Password_strength_checker:

A web page that tests how strong a password is. It checks length, randomness, reuse and common mistakes, and estimates how long an attacker would need to crack it. Open Password Checker.html in a browser and type a password. Nothing is sent anywhere.

5. Sealbox File Encryption
 encrypt_and_decrypt/File Encryption

A web app that locks any file with a password and unlocks it again. It uses the browser's Web Crypto API (PBKDF2 and AES-256-GCM), so your files and password never leave your device. Open index.html, choose a file, enter a password and click encrypt or decrypt.

6. Phishing Link Inspector
 Safety_Checker/Phishing_Link

A web tool that checks a link for common phishing tricks, such as fake brand names, misspelled domains, IP addresses and hidden redirects. It shows which domain the link really goes to, gives a risk score from 0 to 100 and explains each warning sign. Open index.html and paste a link. The link is never opened.

7. TCP Port Scanner
 Safety_Checker

A fast, multi-threaded Python tool that finds open TCP ports on a computer and names the service running on each one. It can also read service banners to show what software is listening. Only scan your own machines or systems you have permission to test.

bash
python "TCP port scanner.py" 127.0.0.1
python "TCP port scanner.py" 192.168.1.10 -p 1-1024 --banner

8. IP Info Finder
 Info_Finder/ip-info-finder

A command-line tool that looks up an IP address or domain name and shows its type, owner, hostname and approximate location. Private addresses are analysed offline and never sent to an online service. See the project's own README for more details.

bash
python ip_info.py 8.8.8.8
python ip_info.py github.com --json

9. Login Authentication System
 Login_Authenticater

A Java console program for registering users and logging in securely. Passwords are stored as salted PBKDF2-HMAC-SHA256 hashes, never in plain text, and accounts are locked after five failed attempts. Compile and run it with Java.

bash
javac LoginSystem.java
java LoginSystem

10. Two-Factor Authenticator
 Two_factor_encryption

A Python version of an authenticator app like Google Authenticator. It generates six-digit TOTP codes (RFC 6238) that work with real two-factor logins. Add an account, then show its codes in the terminal.

bash
python TwoFactorAuthenticator.py add "GitHub"
python TwoFactorAuthenticator.py watch
Requirements
Browser tools (3, 4, 5, 6): any modern browser. No installation needed.
Python tools (1, 2, 7, 8, 10): Python 3.10 or newer. Only the Password Manager needs an extra package (cryptography).
Java tool (9): Java 11 or newer.
