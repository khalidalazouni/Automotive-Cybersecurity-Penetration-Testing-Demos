#!/usr/bin/env python3
import socket
import struct
import threading
import time
import sys
import random 

PORT = 13400

# ======================================================
# ECU Identity & Persistent Data
# ======================================================
VIN_STR = "1ABCDEF1234567890" 
VEH_MODEL = "DEMO-MODEL"
INITIAL_CONFIG = 0xAB
CONFIG = INITIAL_CONFIG

# UDS Session Constants (Standard IDs)
SESSION_DEFAULT = 0x01
SESSION_PROGRAMMING = 0x02
SESSION_EXTENDED = 0x03

# DoIP Logical Addresses
ECU_LOGICAL_ADDRESS = 0x0001
TESTER_LOGICAL_ADDRESS = 0x0010 

ECU_LA_BYTES_2B = ECU_LOGICAL_ADDRESS.to_bytes(2, 'big')
TESTER_LA_BYTES_2B = TESTER_LOGICAL_ADDRESS.to_bytes(2, 'big')

# DoIP Vehicle Identification (VIN + GID + EID + LA)
VIN_BYTES = VIN_STR.encode().ljust(17, b'\x00')
GID = (0x0001).to_bytes(2, 'big')
EID = (0x0001).to_bytes(6, 'big') # Standard EID is 6 bytes (MAC)
VEHICLE_ID_PAYLOAD = VIN_BYTES + GID + EID + ECU_LA_BYTES_2B

# ======================================================
# Self-Test & Routine State (Compatible with CAN ECU)
# ======================================================
speed = 0
rpm = 0
temperature = 20
MAX_SPEED = 1 
MAX_RPM = 1
MAX_TEMP = 21

routine5678_running = False
routine5678_done = False
routine5678_finish_time = 0

# ======================================================
# DoIP & UDS Helper Functions
# ======================================================
def build_header(msg_type: int, payload: bytes) -> bytes:
    protocol_version = 0x02
    inverse_version = 0xFD
    length = len(payload)
    return struct.pack(">BBHI", protocol_version, inverse_version, msg_type, length) + payload

def send_pos_rsp(conn, sid, data):
    uds_response = bytes([sid + 0x40] + data)
    doip_payload = ECU_LA_BYTES_2B + TESTER_LA_BYTES_2B + uds_response
    conn.sendall(build_header(0x8002, doip_payload))
    print(f"[Node C][UDS] Sent POSITIVE Response: 0x{uds_response.hex().upper()}")

def send_nrc(conn, sid, nrc):
    uds_response = bytes([0x7F, sid, nrc])
    doip_payload = ECU_LA_BYTES_2B + TESTER_LA_BYTES_2B + uds_response
    conn.sendall(build_header(0x8002, doip_payload))
    print(f"[Node C][UDS] Sent NEGATIVE Response: 0x{uds_response.hex().upper()}")

# ======================================================
# UDS Service Handlers
# ======================================================

def uds_10(conn, state, data):
    if len(data) != 1: return send_nrc(conn, 0x10, 0x13)
    sub = data[0]
    
    if sub == SESSION_DEFAULT:
        state['session'] = SESSION_DEFAULT
        state['security_granted'] = False 
        return send_pos_rsp(conn, 0x10, [sub])

    if sub in [SESSION_PROGRAMMING, SESSION_EXTENDED]:
        if not state.get('security_granted', False):
            print(f"[Node C] Denied transition to session 0x{sub:02X}: Security Locked.")
            return send_nrc(conn, 0x10, 0x22)
        
        state['session'] = sub 
        return send_pos_rsp(conn, 0x10, [sub])

    return send_nrc(conn, 0x10, 0x12) 

def uds_27(conn, state, data):
    level = data[0]
    if level == 0x01: # Seed
        state['last_seed'] = random.randint(0, 0x000000E7)
        sb = list(struct.pack(">I", state['last_seed']))
        return send_pos_rsp(conn, 0x27, [0x01] + sb)

    if level == 0x02: # Key
        if state.get('last_seed') is None: return send_nrc(conn, 0x27, 0x24)
        if len(data) != 5: return send_nrc(conn, 0x27, 0x13)
        
        key = struct.unpack(">I", bytes(data[1:5]))[0]
        expected = state['last_seed'] ^ 0x11223344
        if key == expected:
            state['security_granted'] = True
            return send_pos_rsp(conn, 0x27, [0x02])
        return send_nrc(conn, 0x27, 0x35)

def uds_22(conn, state, data):
    if len(data) != 2: return send_nrc(conn, 0x22, 0x13)
    did = (data[0] << 8) | data[1]

    if did in [0xF190, 0xF18C]:
        if not state.get('security_granted', False) or state['session'] not in [SESSION_EXTENDED, SESSION_PROGRAMMING]:
            return send_nrc(conn, 0x22, 0x22)

    if did == 0xF190: return send_pos_rsp(conn, 0x22, [0xF1, 0x90] + list(VIN_STR.encode()))
    if did == 0xF18C: return send_pos_rsp(conn, 0x22, [0xF1, 0x8C] + list(VEH_MODEL.encode()))
    if did == 0xF1A0: return send_pos_rsp(conn, 0x22, [0xF1, 0xA0, CONFIG])
    
    return send_nrc(conn, 0x22, 0x31)

def uds_2E(conn, state, data):
    global CONFIG
    if len(data) != 3: return send_nrc(conn, 0x2E, 0x13)
    hi, lo, val = data
    did = (hi << 8) | lo

    if did != 0xF1A0: return send_nrc(conn, 0x2E, 0x31)
    if not state.get('security_granted', False): return send_nrc(conn, 0x2E, 0x33)

    CONFIG = val
    print(f"[Node C] Updated CONFIG (0xF1A0) to: 0x{CONFIG:02X}")
    return send_pos_rsp(conn, 0x2E, [hi, lo])

def uds_31(conn, state, data):
    global routine5678_running, routine5678_done, routine5678_finish_time
    global speed, rpm, temperature

    if len(data) < 3: return send_nrc(conn, 0x31, 0x13)
    
    sub = data[0]
    hi = data[1]
    lo = data[2]
    rid = (hi << 8) | lo

    # --- SELF-TEST ROUTINE 0x1234 ---
    if rid == 0x1234:
        if not state.get('security_granted', False): return send_nrc(conn, 0x31, 0x33)

        speed += 1
        rpm += 1
        temperature += 1

        speed_ok = 1 if speed <= MAX_SPEED else 0
        rpm_ok = 1 if rpm <= MAX_RPM else 0
        temp_ok = 1 if temperature <= MAX_TEMP else 0
        config_ok = 1

        if speed > MAX_SPEED: speed = 0
        if rpm > MAX_RPM: rpm = 0
        if temperature > MAX_TEMP: temperature = 20

        result = (speed_ok << 4) | (rpm_ok << 3) | (temp_ok << 2) | (config_ok << 1)
        return send_pos_rsp(conn, 0x31, [sub, hi, lo, result])

    # --- CHECKSUM ROUTINE 0x5678 ---
    elif rid == 0x5678:
        if not state.get('security_granted', False): return send_nrc(conn, 0x31, 0x33)
        if state['session'] not in [SESSION_EXTENDED, SESSION_PROGRAMMING]:
            return send_nrc(conn, 0x31, 0x22)

        if sub == 0x01: # Start Routine
            if routine5678_running: return send_nrc(conn, 0x31, 0x78)
            routine5678_running = True
            routine5678_done = False
            routine5678_finish_time = time.time() + 1.0
            return send_pos_rsp(conn, 0x31, [sub, hi, lo])

        elif sub == 0x03: # Request Results
            if routine5678_running: return send_nrc(conn, 0x31, 0x78)
            if not routine5678_done: return send_nrc(conn, 0x31, 0x22)

            vin_bytes = list(VIN_STR.encode())
            checksum = (sum(vin_bytes) + CONFIG) & 0xFFFF
            routine5678_done = False
            return send_pos_rsp(conn, 0x31, [sub, hi, lo, (checksum >> 8) & 0xFF, checksum & 0xFF])
        
        else: return send_nrc(conn, 0x31, 0x12)

    return send_nrc(conn, 0x31, 0x31)

def uds_11(conn, state, data):
    global CONFIG, routine5678_running, routine5678_done, routine5678_finish_time
    state['session'] = SESSION_DEFAULT
    state['security_granted'] = False
    state['last_seed'] = None
    CONFIG = 0xAB
    routine5678_running = False
    routine5678_done = False
    routine5678_finish_time = 0
    return send_pos_rsp(conn, 0x11, [data[0]])

# ======================================================
# Main DoIP Server Logic
# ======================================================
UDS_HANDLERS = {
    0x10: uds_10, 
    0x22: uds_22, 
    0x2E: uds_2E, 
    0x27: uds_27, 
    0x31: uds_31, 
    0x11: uds_11
}

def handle_uds_session(conn, addr):
    global routine5678_running, routine5678_done
    state = {'session': SESSION_DEFAULT, 'security_granted': False, 'last_seed': None}
    print(f"[Node C][TCP] UDS Session started with {addr}")
    
    try:
        while True:
            # Handle Async Routine completion for compatibility
            if routine5678_running and time.time() >= routine5678_finish_time:
                routine5678_running = False
                routine5678_done = True

            conn.settimeout(0.1) 
            try:
                header = conn.recv(8)
            except socket.timeout:
                continue

            if not header: break
            
            v, inv_v, msg_type, length = struct.unpack(">BBHI", header)
            payload = conn.recv(length)
            
            if msg_type == 0x8001: # Diagnostic Message
                uds_sid = payload[4] 
                uds_data = list(payload[5:])
                print(f"[Node C][UDS] Received Request: SID 0x{uds_sid:02X}")
                
                handler = UDS_HANDLERS.get(uds_sid)
                if handler:
                    handler(conn, state, uds_data)
                else:
                    send_nrc(conn, uds_sid, 0x11)
            
            elif msg_type == 0x3E: # Alive Check
                conn.sendall(build_header(0x0008, ECU_LA_BYTES_2B))

    except Exception as e:
        print(f"[Node C][TCP] Session error: {e}")
    finally:
        conn.close()
        print(f"[Node C][TCP] Session with {addr} closed.")

def start_ecu():
    print("Starting DoIP ECU Simulator with full UDS logic...")
    
    def udp_discovery():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', PORT))
        print(f"[Node C] Listening for UDP DoIP discovery on port {PORT}")
        while True:
            data, addr = sock.recvfrom(1024)
            if len(data) >= 4 and struct.unpack(">H", data[2:4])[0] == 0x0001:
                print(f"[Node C][UDP] Received 0x0001 from {addr}. Responding...")
                sock.sendto(build_header(0x0004, VEHICLE_ID_PAYLOAD), addr)
                print(f"[Node C][UDP] Sent 0x0004 Vehicle ID Response to {addr}")

    threading.Thread(target=udp_discovery, daemon=True).start()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', PORT))
    server.listen(5)
    print(f"[Node C] Listening for TCP routing activation on port {PORT}")

    while True:
        conn, addr = server.accept()
        data = conn.recv(1024)
        if len(data) >= 8 and struct.unpack(">H", data[2:4])[0] == 0x0005:
            tester_la = struct.unpack(">H", data[8:10])[0]
            if tester_la == TESTER_LOGICAL_ADDRESS:
                print(f"[Node C][TCP] Received 0x0005 from {addr}. Tester LA 0x{tester_la:04X} MATCHES.")
                res = TESTER_LA_BYTES_2B + ECU_LA_BYTES_2B + b'\x00' + b'\x00'*8
                conn.sendall(build_header(0x0006, res))
                print(f"[Node C][TCP] Sent 0x0006 Routing Activation Response with code: 0x00")
                threading.Thread(target=handle_uds_session, args=(conn, addr), daemon=True).start()
            else:
                print(f"[Node C][TCP] Invalid Tester LA: 0x{tester_la:04X}. Closing.")
                conn.close()

if __name__ == "__main__":
    try:
        start_ecu()
    except KeyboardInterrupt:
        print("\n[Node C] ECU Offline.")
        sys.exit(0)
