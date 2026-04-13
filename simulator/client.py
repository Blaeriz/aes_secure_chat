import socket
import ssl
import simplefix
import time
import argparse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import binascii

class SecurityLayer:
    def __init__(self, aes_enabled, hex_key):
        self.aes_enabled = aes_enabled
        if aes_enabled:
            self.aesgcm = AESGCM(binascii.unhexlify(hex_key))
    
    def encrypt_message(self, raw_fix):
        if not self.aes_enabled:
            return raw_fix
        
        # 8=FIX.4.2\x019=XXX\x01BODY...10=XXX\x01
        tag9_idx = raw_fix.find(b"\x019=")
        if tag9_idx == -1: return raw_fix
        
        body_start = raw_fix.find(b"\x01", tag9_idx + 3)
        if body_start == -1: return raw_fix
        body_start += 1
        
        tag10_idx = raw_fix.find(b"\x0110=", body_start)
        if tag10_idx == -1: return raw_fix
        
        body = raw_fix[body_start:tag10_idx]
        nonce = bytearray(12) # For simplicity, use zeros or random. Spec says 12-byte nonce.
        # Actually should use random
        import os
        nonce = os.urandom(12)
        
        ciphertext = self.aesgcm.encrypt(nonce, body, None)
        encrypted_body = nonce + ciphertext # ciphertext includes 16-byte tag at the end in cryptography lib
        
        header_prefix = raw_fix[:tag9_idx + 3]
        new_msg = header_prefix + str(len(encrypted_body)).encode() + b"\x01" + encrypted_body
        
        checksum = (sum(new_msg) + 1) % 256
        return new_msg + b"\x01" + b"10=" + f"{checksum:03d}".encode() + b"\x01"

    def decrypt_message(self, raw_fix):
        if not self.aes_enabled:
            return raw_fix
        
        tag9_idx = raw_fix.find(b"\x01" + b"9=")
        if tag9_idx == -1: return raw_fix
        
        body_start = raw_fix.find(b"\x01", tag9_idx + 3)
        if body_start == -1: return raw_fix
        body_start += 1
        
        tag10_idx = raw_fix.find(b"\x01" + b"10=", body_start)
        if tag10_idx == -1: return raw_fix
        
        encrypted_body = raw_fix[body_start:tag10_idx]
        nonce = encrypted_body[:12]
        ciphertext = encrypted_body[12:]
        
        decrypted_body = self.aesgcm.decrypt(nonce, ciphertext, None)
        
        header_prefix = raw_fix[:tag9_idx + 3]
        new_msg = header_prefix + str(len(decrypted_body)).encode() + b"\x01" + decrypted_body
        
        checksum = (sum(new_msg) + 1) % 256
        return new_msg + b"\x01" + b"10=" + f"{checksum:03d}".encode() + b"\x01"

def create_logon(sender_comp_id, target_comp_id, seq_num):
    msg = simplefix.FixMessage()
    msg.append_pair(8, "FIX.4.2")
    msg.append_pair(35, "A")
    msg.append_pair(49, sender_comp_id)
    msg.append_pair(56, target_comp_id)
    msg.append_pair(34, seq_num)
    msg.append_utc_timestamp(52)
    msg.append_pair(98, 0)
    msg.append_pair(108, 30)
    return msg

def create_order(sender_comp_id, target_comp_id, seq_num, symbol, qty, price, side):
    msg = simplefix.FixMessage()
    msg.append_pair(8, "FIX.4.2")
    msg.append_pair(35, "D")
    msg.append_pair(49, sender_comp_id)
    msg.append_pair(56, target_comp_id)
    msg.append_pair(34, seq_num)
    msg.append_utc_timestamp(52)
    msg.append_pair(11, f"ORD{seq_num}")
    msg.append_pair(55, symbol)
    msg.append_pair(54, side)
    msg.append_pair(38, qty)
    if price:
        msg.append_pair(40, "2")
        msg.append_pair(44, price)
    else:
        msg.append_pair(40, "1")
    return msg

def main():
    parser = argparse.ArgumentParser(description="FIX Client Simulator")
    parser.add_argument("--host", default="127.0.0.1", help="Server host")
    parser.add_argument("--port", type=int, default=9878, help="Server port")
    parser.add_argument("--sender", default="CLIENT1", help="SenderCompID")
    parser.add_argument("--target", default="EXCHANGE", help="TargetCompID")
    parser.add_argument("--aes-key", default="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    
    args = parser.parse_args()

    security = SecurityLayer(True, args.aes_key)
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s = context.wrap_socket(raw_socket, server_hostname=args.host)

    try:
        s.connect((args.host, args.port))
        print(f"Connected (TLS + AES)")

        seq = 1
        logon = create_logon(args.sender, args.target, seq)
        s.send(security.encrypt_message(logon.encode()))
        seq += 1

        resp = s.recv(4096)
        print("Received Logon ACK")

        order = create_order(args.sender, args.target, seq, "AAPL", 100, None, "1")
        s.send(security.encrypt_message(order.encode()))
        seq += 1

        resp = s.recv(4096)
        dec = security.decrypt_message(resp)
        print(f"Received ExecReport: {dec}")

        logout = simplefix.FixMessage()
        logout.append_pair(8, "FIX.4.2")
        logout.append_pair(35, "5")
        logout.append_pair(49, args.sender)
        logout.append_pair(56, args.target)
        logout.append_pair(34, seq)
        logout.append_utc_timestamp(52)
        s.send(security.encrypt_message(logout.encode()))

    except Exception as e:
        print(f"Error: {e}")
    finally:
        s.close()

if __name__ == "__main__":
    main()
