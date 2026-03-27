import sys
import base64
import json
import os
import re
import requests
import urllib3
import hmac
import hashlib
import time
import math
import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from gmpy2 import mpz, gcd, c_div

# Suppress warnings for Lab environments
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
sys.set_int_max_str_digits(0)

# ANSI Escape Codes
RED = "\033[1;31m"
RESET = "\033[0m"
CYAN = "\033[1;36m"
YELLOW = "\033[1;33m"
PURPLE = "\033[1;35m"
GREEN = "\033[1;32m"
MAGENTA = "\033[35m"

# --- SHARED HELPERS ---

def get_wordlist_path(filename):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    path = os.path.join(base_dir, "Wordlists", filename)
    return path

def get_claims():
    path = get_wordlist_path("claims.txt")
    if os.path.exists(path):
        with open(path, "r") as f:
            content = f.read().replace('\n', ',')
            return [c.strip().lower() for c in content.split(',') if c.strip() and not c.startswith('#')]
    return ["admin", "root", "role", "sub", "id", "user"]

SENSITIVE_CLAIMS = get_claims()

def b64_e(data):
    if isinstance(data, str): data = data.encode()
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip("=")

def b64_d(data):
    missing_padding = len(data) % 4
    if missing_padding: data += '=' * (4 - missing_padding)
    return base64.urlsafe_b64decode(data)

def generate_rsa_jwk():
    unique_kid = f"jwtmap-{hashlib.md5(os.urandom(16)).hexdigest()[:8]}"
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nums = priv.public_key().public_numbers()
    n = b64_e(nums.n.to_bytes((nums.n.bit_length() + 7) // 8, 'big'))
    e = b64_e(nums.e.to_bytes((nums.e.bit_length() + 7) // 8, 'big'))
    jwk_dict = {"kty": "RSA", "e": e, "n": n, "kid": unique_kid, "alg": "RS256", "use": "sig"}
    return priv, jwk_dict

def bytes2mpz(b):
    return mpz(int(b.hex(), 16))

