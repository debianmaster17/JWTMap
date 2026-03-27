import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from helpers import *

def start_payload_scan():
    token = input(f"\n{YELLOW}[?] Enter JWT token: {RESET}").strip()
    parts = token.split('.')
    if len(parts) < 2: 
        print(f"{RED}[!] Invalid JWT structure.{RESET}")
        return
        
    try:
        payload_data = json.loads(b64_d(parts[1]))
        
        print(f"\n{CYAN}[*] Scanning Payload for sensitive claims...{RESET}")
        found = False
        
        for key, val in payload_data.items():
            if any(word in key.lower() for word in SENSITIVE_CLAIMS):
                print(f"{RED}[!] FLAG: '{key}': {val}{RESET}")
                found = True
                
        if not found:
            print(f"{YELLOW}[*] No sensitive claims identified.{RESET}")
            
    except Exception as e: 
        print(f"{RED}[!] Error: {e}{RESET}")
        
    input(f"\n{CYAN}[>] Press Enter to return to menu...{RESET}")