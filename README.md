# JWTMap - JWT EXPLOITATION FRAMEWORK

**JWTMap** is a Python tool designed for security researchers and penetration testers to automate the discovery and exploitation of common and advanced JSON Web Token (JWT) vulnerabilities.

From standard algorithm downgrades to advanced cryptographic modulus recovery, **JWTMap** provides a modular "arsenal" for testing modern web authentication layers.

---

## 🚀 Key Features

### 1. **Signature & Algorithm Attacks**

- **Algorithm Confusion (RS256 ➔ HS256):** Automates the conversion of a Public Key (X.509/PKCS#1/DER) into an HMAC secret.
    
- **Sig2n Modulus Recovery:** Uses GMPY2 to mathematically derive the RSA modulus (n) from two unique JWT signatures to perform algorithm confusion without a known public key.
    
- **Algorithm Downgrade:** Generates "alg: none" exploits with mixed-case fuzzing to bypass weak WAF filters.
    
### 2. **JOSE Header Injections**

- **x5c (X.509 Certificate Chain):** Injects a self-signed certificate into the header to trick the server into trust.
    
- **JWK/JKU Injection:** Embeds or hosts a malicious JSON Web Key to forge signatures.
    
- **KID Path Traversal:** Exploits `kid` (Key ID) headers to force the server to sign tokens using static files like `/dev/null`.
    
- **CTY (Content-Type) Injection:** Manipulates the `cty` header to force the backend into processing the payload as `xml` (XXE) or `java-serialized-object` (Insecure Deserialization).
    
### 3. **Intelligence & Utility**

- **Payload Scanner:** Automatically cross-references JWT claims against a customizable sensitive wordlist (`claims.txt`).
    
- **Offline Brute Force:** High-speed HMAC secret cracking with integrated forgery tools.

---
## 📁 Project Structure

```Plaintext
JWTMap/
├── jwtmap.py           # Main entry point & CLI Menu
├── helpers.py          # Cryptographic Engine & Shared Utilities
├── Attacks/            # Modular Attack Logic
│   ├── __init__.py     
│   ├── alg_confusion.py
│   ├── jose_injections.py
|   ├── payload_scan.py
│   └── brute_force.py
|   
└── Wordlists/          # Dictionary Files
    ├── claims.txt      # Sensitive claim names
    ├── exposed_keys.txt # Directory fuzzing for exposed JWK sets     
    └── secrets.txt     # HMAC secrets for cracking
```

## 🛠️ Installation

### **Prerequisites**

- **Python 3.8+**
    
- **C Compiler/Header Files:** Required for the `gmpy2` library (used for high-speed crypto-math).
    
    - _Debian/Ubuntu:_ `sudo apt install libmpc-dev`
        
    - _Windows:_ Install the [Microsoft C++ Build Tools](https://www.google.com/search?q=https://visualstudio.microsoft.com/visual-cpp-build-tools/).
        
### **Setup**

1.**Clone the Repository:**

```Bash
git clone https://github.com/debianmaster17/JWTMap && cd /JWTMap
```

2.**Install Dependencies:**

```Bash
pip3 install -r requirements.txt
```

3.**Run the Tool:**

```Bash
python3 jwtmap.py
```

## 📋 Requirements

The following libraries are required and handled by the installation step above:

- `requests`: For live target testing.
    
- `cryptography`: For RSA, X.509, and certificate generation.
    
- `gmpy2`: For advanced modular arithmetic and GCD operations.
    
- `urllib3`: For handling insecure lab environments.

## ⚠️ Disclaimer

**This tool is for educational and authorized penetration testing purposes only.** Usage of JWTMap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

---

**Author:**  Alpay Ibrahimli (debianmaster17)

**License:** MIT

---
