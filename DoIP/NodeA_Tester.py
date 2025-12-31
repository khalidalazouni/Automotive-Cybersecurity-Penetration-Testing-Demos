#!/usr/bin/env python3
# NodeA_Tester_UDS_Automated_Flow_V8.py (Updated for Node C's 22-byte 0x0004 payload)
import socket
import struct
import time
import sys
import re

PORT = 13400
# --- CONFIGURATION POINT: CHANGE THIS TO CHANGE THE TESTER'S LA ---
TESTER_LOGICAL_ADDRESS = 0x10
# ------------------------------------------------------------------

# ==========================================
# Color codes
# ==========================================
GREEN = "\033[92m"
RED     = "\033[91m"
CYAN  = "\033[96m"
RESET = "\033[0m"
YELLOW = "\033[93m"

print(CYAN + "Starting DoIP Tester: Automated Discovery and Routing..." + RESET)

# ==========================================
# DoIP Utility Functions
# ==========================================
def build_header(msg_type: int, payload: bytes) -> bytes:
    protocol_version = 0x02
    inverse_version = 0xFD
    length = len(payload)
    # >BBHI: Big-Endian (Network Byte Order)
    return struct.pack(">BBHI", protocol_version, inverse_version, msg_type, length) + payload

# ==========================================
# UDS Core Functions (Uses the 'tester_la' argument passed from main)
# ==========================================
def uds_request(sock: socket.socket, ecu_la: int, tester_la: int, sid: int, data_bytes: list, silent=False):
    
    # 2-byte representation of the LAs
    ECU_LA_BYTES = ecu_la.to_bytes(2, 'big')      # Target LA (e.g., 0x0001)
    TESTER_LA_BYTES = tester_la.to_bytes(2, 'big') # Source LA (e.g., 0x0030)

    uds_payload = bytes([sid] + data_bytes)
    
    if not silent:
        print(f">> Sending UDS: {uds_payload.hex().upper()}")

    # 0x8001 Payload: Source LA (Tester) + Target LA (ECU) + UDS Payload
    doip_payload = TESTER_LA_BYTES + ECU_LA_BYTES + uds_payload

    # 1. Wrap DoIP payload in DoIP 0x8001 Diagnostic Message Request
    uds_request_msg = build_header(0x8001, doip_payload)
    
    # 2. Send the DoIP message over the established TCP socket
    try:
        sock.send(uds_request_msg)
        
        # 3. Wait for DoIP 0x8002 Diagnostic Message Reply
        sock.settimeout(5)
        data = sock.recv(1024)
        
        if len(data) >= 8:
            reply_msg_type = struct.unpack(">H", data[2:4])[0]
            reply_payload = data[8:]

            if reply_msg_type == 0x8002:
                # 0x8002 Payload: Source LA (ECU) + Target LA (Tester) + UDS Response
                resp = reply_payload[4:] # Extract UDS response starting after the 4 LA bytes
                
                if not silent:
                    print(f"<< UDS Reply: {resp.hex().upper()}")
                    decode_response(resp)

                handle_auto_security(sock, ecu_la, tester_la, resp)
                return resp
            else:
                if not silent:
                    print(RED + f"!! Received unexpected DoIP message type: 0x{reply_msg_type:04X}" + RESET)
        
    except socket.timeout:
        if not silent:
            print(RED + "!! NO RESPONSE (timeout)" + RESET)
    except Exception as e:
        if not silent:
            print(RED + f"!! Communication Error: {e}" + RESET)

    return None

def handle_auto_security(sock: socket.socket, ecu_la, tester_la, resp):
    if len(resp) < 6: return
    # Check for 0x67 0x01 (Positive response to Security Access Request for Seed)
    if resp[0] == 0x67 and resp[1] == 0x01:      
        seed = (resp[2] << 24) | (resp[3] << 16) | (resp[4] << 8) | resp[5]
        key = seed ^ 0x11223344      
        key_bytes = [(key >> 24) & 0xFF, (key >> 16) & 0xFF, (key >> 8) & 0xFF, key & 0xFF]

        print(YELLOW + f"--> Seed: 0x{seed:08X}" + RESET)
        print(YELLOW + f"--> Key:  0x{key:08X} (sending automatically)" + RESET)

        time.sleep(0.3)
        # Send Security Access Key (level 02)
        uds_request(sock, ecu_la, tester_la, 0x27, [0x02] + key_bytes, silent=False)

def decode_response(resp):
    sid = resp[0]
    
    # ReadDataByIdentifier Response (0x62)
    if sid == 0x62:
        if len(resp) < 3: return
        did = (resp[1] << 8) | resp[2]
        data = resp[3:]

        print(CYAN + "\n[Decoded DID Response]" + RESET)
        print(f"  DID: 0x{did:04X}")

        try:
            ascii_data = bytes(data).decode("ascii")
            if ascii_data.isprintable():
                print(f"  Value: {ascii_data}\n")
                return
        except:
            pass
        print(f"  Value (hex): {data.hex().upper()}\n")
        return

    # RoutineControl Response (0x71)
    if sid == 0x71:
        if len(resp) < 4: return
        sub = resp[1]
        rid = (resp[2] << 8) | resp[3]
        data = resp[4:]

        print(CYAN + "\n[Decoded Routine Response]" + RESET)
        print(f"  RID: 0x{rid:04X}")

        if rid == 0x1234:
            if len(data) > 0:
                result = data[0]
                print("  Routine: 0x1234 — Self-Test")
                print(f"    Speed OK:    {(result >> 4) & 1}")
                print(f"    RPM OK:      {(result >> 3) & 1}")
                print(f"    Temp OK:     {(result >> 2) & 1}")
                print(f"    Config OK:   {(result >> 1) & 1}\n")
            return

        elif rid == 0x5678:
            print("  Routine: 0x5678 — Checksum/Control")
            if sub == 0x01:
                print("    Subfunction 01: Started")
                return
            elif sub == 0x03 and len(data) >= 2:
                checksum = (data[0] << 8) | data[1]
                print(f"    Subfunction 03: Read Results")
                print(f"    Checksum: 0x{checksum:04X}\n")
                return
            else:
                print(f"    Subfunction {sub:02X}: Not supported/Unexpected length\n")
                return
            
        else:
              print(f"  Subfunction {sub:02X}, Data (hex): {data.hex().upper()}\n")

# ==========================================
# Automated Connection Flow  
# ==========================================
def udp_discovery(timeout=3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(timeout)

    payload = b''      
    request = build_header(0x0001, payload)
    sock.sendto(request, ('255.255.255.255', PORT))
    print("[Node A] 1/2. Broadcasted 0x0001 Vehicle Identification Request...")

    ecus = []
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            data, addr = sock.recvfrom(1024)
            # *** MODIFIED: Expected payload length reduced from 23 to 22 bytes ***
            if len(data) >= 22 + 8:
                msg_type = struct.unpack(">H", data[2:4])[0]
                payload = data[8:]

                if msg_type == 0x0004:
                    vin = payload[:17].decode(errors="ignore")
                    # ECU LA is now at index 20 (17 VIN + 2 GID + 2 EID = 21st byte, 0-indexed)
                    ecu_la = payload[20]
                    # The preferred Tester LA byte is no longer present in the 0x0004 response
                    
                    print(GREEN + f"[Node A] Discovered ECU at {addr[0]} VIN:{vin} ECU LA:0x{ecu_la:02X}" + RESET)
                    # Pass a placeholder (None) for the preferred LA since it's not present
                    ecus.append((addr[0], ecu_la, None)) 
        except socket.timeout:
            break
        except Exception:      
            pass
    sock.close()
    return ecus

def tcp_routing_activation(ecu_ip, tester_la):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((ecu_ip, PORT))
        print(f"[Node A] 2/2. TCP Connected to ECU {ecu_ip}")

        # 1. SEND 0x0005 (Routing Activation Request)
        # We use the configured 'tester_la' here.
        payload = tester_la.to_bytes(2, 'big') + b'\x00' + b'\x00\x00\x00\x00'
        request = build_header(0x0005, payload)
        sock.send(request)
        print(f"[Node A] Sending 0x0005 Routing Activation Request with LA 0x{tester_la:04X}...")
        
        # 2. WAIT FOR 0x0006 (Routing Activation Response)
        sock.settimeout(5)
        data = sock.recv(1024)
        
        if len(data) >= 8 + 13:      
            msg_type = struct.unpack(">H", data[2:4])[0]
            
            if msg_type == 0x0006:
                response_code = data[12]
                if response_code == 0x00:
                    print(GREEN + f"[Node A] Received 0x0006 SUCCESS (Code 0x00)." + RESET)
                    return sock
                else:
                    print(RED + f"[Node A] Routing Failed: Received 0x0006 Negative Response (Code 0x{response_code:02X})." + RESET)
                    sock.close()
                    return None
            else:
                print(RED + f"[Node A] Routing Failed: Received unexpected message 0x{msg_type:04X}." + RESET)
                sock.close()
                return None
        else:
            print(RED + "[Node A] Routing Failed: Did not receive a valid 0x0006 response (length too short)." + RESET)
            sock.close()
            return None

    except socket.timeout:
        print(RED + "[Node A] Routing Failed: TCP communication timed out." + RESET)
        return None
    except Exception as e:
        print(RED + f"[Node A] Routing Failed: TCP connection error: {e}" + RESET)
        return None

def interactive_session(sock, ecu_la, tester_la):
    print("\n" + GREEN + "==================================================" + RESET)
    print(GREEN + "!!! CONNECTION SUCCEEDED: START UDS SESSION !!!" + RESET)
    print(f"!!! ECU LA: 0x{ecu_la:02X}, Tester LA: 0x{tester_la:04X} !!!" + RESET)
    print(GREEN + "==================================================" + RESET)
    print("Commands:")
    print(" - Enter UDS request as space-separated hex bytes, e.g., '10 03' or '22 F1 81'")
    print(" - q = quit session\n")

    while True:
        cmd_in = input(f"{YELLOW}UDS Request (hex bytes):{RESET} ").strip().lower()

        if cmd_in == "q":
            break
        
        hex_bytes = re.findall(r'[0-9a-fA-F]{1,2}', cmd_in)

        if not hex_bytes:
            print(RED + "Invalid input. Please enter hex bytes (e.g., '10 03')." + RESET)
            continue

        try:
            uds_bytes = [int(x, 16) for x in hex_bytes]
            
            if not uds_bytes:
                print(RED + "No valid UDS bytes provided." + RESET)
                continue

            sid = uds_bytes[0]
            data_bytes = uds_bytes[1:]

            # IMPORTANT: Using the configured TESTER_LOGICAL_ADDRESS (via tester_la)
            uds_request(sock, ecu_la, tester_la, sid, data_bytes)
            print()

        except Exception as e:
            print(RED + f"Error processing input: {e}" + RESET)
            continue

# ==========================================
# Main Program Entry  
# ==========================================
if __name__ == "__main__":
    
    # Use the global constant for the tester's LA in all communications
    tester_la_to_use = TESTER_LOGICAL_ADDRESS
    
    while True:
        user_input = input(f"{CYAN}Enter 'connect' to search for ECU (or 'q' to quit):{RESET} ").strip().lower()
        if user_input == 'connect':
            break
        elif user_input == 'q':
            sys.exit(0)
        else:
            print(RED + "Invalid command. Please enter 'connect' or 'q'." + RESET)
            
    active_sock = None
    try:
        # Step 1: Automatic Discovery (UDP)
        discovered_ecus = udp_discovery(timeout=3)
        
        if not discovered_ecus:
            print(RED + "[Node A] NO ECUs discovered. Exiting." + RESET)
            sys.exit(0)

        # Retrieve the ECU's IP and its own LA. The third element is now None.
        first_ecu_ip, ecu_la, _ = discovered_ecus[0] 
        
        print(f"{YELLOW}Using configured Tester Logical Address: 0x{tester_la_to_use:04X}{RESET}")
        
        # Step 2: Automatic Routing Activation (TCP)
        # Pass the configured LA for the 0x0005 request.
        active_sock = tcp_routing_activation(first_ecu_ip, tester_la_to_use) 

        if active_sock:
            # Step 3 & 4: Start interactive session
            # Pass the configured LA for all UDS requests.
            interactive_session(active_sock, ecu_la, tester_la_to_use)
        
        else:
             print(RED + "[Node A] Could not activate routing. Exiting." + RESET)

    except KeyboardInterrupt:
        print("\n[Node A] Tester stopped by user.")
        sys.exit(0)
    finally:
        if active_sock:
            active_sock.close()
            print("[Node A] TCP socket closed.")
