import sys
import os

logo = r"""            
  __   __  __    __  _____                    __    
 / /   \ \/ / /\ \ \/__   \   /\/\   __ _ _ __\ \   
/ /     \ \ \/  \/ /  / /\/  /    \ / _` | '_ \\ \  
\ \  /\_/ /\  /\  /  / /    / /\/\ \ (_| | |_) / /  
 \_\ \___/  \/  \/   \/     \/    \/\__,_| .__/_/   
                                         |_|       by debianmaster17"""


from helpers import RED, RESET, CYAN

from Attacks.alg_confusion import alg_confusion_menu
from Attacks.jose_injections import jose_menu
from Attacks.brute_force import bruteforce_and_forge
from Attacks.payload_scan import start_payload_scan

def main_menu():
    while True:
        print(f"{RED}{logo}{RESET}")
        print(f"{CYAN}           JWT EXPLOITATION FRAMEWORK {RESET}")
        print(f"\n{RED}=================================================={RESET}")
        print("1. Payload Scan - Identify Sensitive Claims")
        print("2. Algorithm Confusion Attacks - Signature Bypass")
        print("3. Offline Secret-key Cracking & JWT Forgery (HS256)")
        print("4. JOSE Header Injections (x5c,cty,jwk,jku,kid)")
        print("5. Exit")
        print(f"{RED}=================================================={RESET}")
        
        choice = input(f"\n{CYAN}jwtmap > {RESET}").strip()
        
        if choice == '1': start_payload_scan()
        elif choice == '2': alg_confusion_menu()
        elif choice == '3': bruteforce_and_forge()
        elif choice == '4': jose_menu()
        elif choice == '5':
            print(f"{RED}[*] Shutting down JWTMap...{RESET}")
            sys.exit()

if __name__ == "__main__":
    main_menu()