import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

class EndToEndEncryption:
    def __init__(self, key: bytes = None):
        """
        Initialize with a 256-bit key for AES-GCM.
        If no key is provided, a random one is generated.
        """
        if key is None:
            key = AESGCM.generate_key(bit_length=256)
        if len(key) not in {16, 24, 32}:
            raise ValueError("Key must be 128, 192, or 256 bits long.")
        self.key = key
        self.aesgcm = AESGCM(self.key)

    def encrypt(self, plaintext: str) -> bytes:
        nonce = os.urandom(12)
        ciphertext = self.aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        return nonce + ciphertext

    def decrypt(self, ciphertext: bytes) -> str:
        nonce = ciphertext[:12]
        ct = ciphertext[12:]
        plaintext_bytes = self.aesgcm.decrypt(nonce, ct, None)
        return plaintext_bytes.decode('utf-8')

class ChatEncryption:
    """
    This class uses a shared master key to derive a unique key for every message.
    An internal counter is used as salt for HKDF. The encrypted data contains:
       8 bytes: counter (big endian)
      12 bytes: random nonce for AES-GCM
      remaining: ciphertext from AES-GCM encryption
    """
    def __init__(self, master_key: bytes):
        if len(master_key) not in {16, 24, 32}:
            raise ValueError("Master key must be 128, 192, or 256 bits long.")
        self.master_key = master_key
        self.send_counter = 0

    def _derive_key(self, counter: int) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key for AES-GCM
            salt=counter.to_bytes(8, 'big'),
            info=b'chat-message-key'
        )
        return hkdf.derive(self.master_key)

    def encrypt(self, plaintext: str) -> bytes:
        # Derive a per-message key from the master key using the current counter as salt.
        key = self._derive_key(self.send_counter)
        counter_bytes = self.send_counter.to_bytes(8, 'big')
        self.send_counter += 1
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)  # AES-GCM nonce
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        # Message format: counter (8 bytes) + nonce (12 bytes) + ciphertext
        return counter_bytes + nonce + ciphertext

    def decrypt(self, data: bytes) -> str:
        # Extract the counter from the message
        counter = int.from_bytes(data[:8], 'big')
        nonce = data[8:20]
        ciphertext = data[20:]
        key = self._derive_key(counter)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext

# Example usage for ChatEncryption:
if __name__ == "__main__":
    # In practice, use a securely shared master key between server and client.
    master_key = os.urandom(32)  # For demonstration only
    chat_enc = ChatEncryption(master_key)
    
    message = "This is a secret chat message."
    encrypted = chat_enc.encrypt(message)
    print("Encrypted data:", encrypted)
    
    decrypted = chat_enc.decrypt(encrypted)
    print("Decrypted message:", decrypted)