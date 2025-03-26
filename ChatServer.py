import socket
from log import Logger
import os
import rsa
import pickle
from ENV import *

# In a real application, the master key needs to be securely exchanged.
# SHARED_MASTER_KEY = b'3%\xca\xff\xe5\x9f\x00\x0eK%\x99\xaa\xca\tU|\xcc\xf3\xc5:\xce\x15\xe0\x94\\\xcd\x15H\x1aL \xcc'  # Example for demonstration


class ChatServer:
    def __init__(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('localhost', 25565))
        self.server_socket.settimeout(5)
        self.Logger = Logger('SERVER')
        # self.encryption = ChatEncryption(SHARED_MASTER_KEY)
        # self.exchange_new_keys()
        # publicKey, privateKey = rsa.newkeys(KEY_SIZE)
        # self.publicKey = publicKey
        # self.privateKey = privateKey
        # self.otherPublicKey = None
        # self.Logger.warning(f"Private key: {self.publicKey}")
        # self.Logger.info(f"Length of public key: {len(self.publicKey.save_pkcs1())}")


    def start(self):
        self.server_socket.listen(1)
        try:
            self.connection, address = self.server_socket.accept()
            self.Logger.info(f"Connection from {address}")
            
            self.exchange_new_keys()
            # # Receive the public key from the client
            # self.Logger.info("Waiting for public key")
            # self.otherPublicKey = rsa.PublicKey.load_pkcs1(self.connection.recv(len(self.publicKey.save_pkcs1())))
            # self.Logger.info(f"Public key received: {self.otherPublicKey}")
            
            #  # Send the public key to the client
            # self.connection.send(self.publicKey.save_pkcs1())
            # self.Logger.info("Public key sent")
        except Exception as e:
            self.Logger.error("No connection incoming")
            exit(0)

    
    def exchange_new_keys(self):
        # Generate new keys
        publicKey, privateKey = rsa.newkeys(KEY_SIZE)
        self.publicKey = publicKey
        self.privateKey = privateKey

        # Receive the public key from the client
        self.Logger.info("Waiting for public key")
        self.otherPublicKey = rsa.PublicKey.load_pkcs1(self.connection.recv(len(self.publicKey.save_pkcs1())))
        # self.Logger.info(f"Public key received: {self.otherPublicKey}")
        
         # Send the public key to the client
        self.connection.send(self.publicKey.save_pkcs1())
        # self.Logger.info("Public key sent")
        self.Logger.success("Exchanged new keys")


    def send_message(self, message):
        if isinstance(message, (str, int, float)):
            message = message.encode('utf-8')  # Ensure the message is in bytes
        if self.otherPublicKey is None:
            self.Logger.error("Cannot send message, otherPublicKey is None")
            return
        try:
            encrypted = rsa.encrypt(message, self.otherPublicKey)
            self.connection.send(encrypted)
        except Exception as e:
            self.Logger.error(f"Error sending message: {e}")

    def recv_fixed(self, size):
        data = b''
        while len(data) < size:
            packet = self.connection.recv(size - len(data))
            if not packet:
                break
            data += packet
        return data


    def receive_message(self):
        block_size = KEY_SIZE // 8  # RSA ciphertext block size in bytes
        data = self.recv_fixed(block_size)
        return rsa.decrypt(data, self.privateKey).decode('utf-8')


    def recv_file(self, end_to_end: bool = False) -> None:
        if end_to_end:
            self.Logger.warning("End-to-end encryption is enabled")
        fileName = self.receive_message()  # File name is sent as a regular message
        fileSize = int(self.receive_message())  # File size is sent as a regular message
        self.Logger.info(f"RECEVING FILE | File name: {fileName} | File size: {fileSize}")

        os.makedirs("RECV_FOLDER", exist_ok=True)  # Ensure the folder exists
        block_size = KEY_SIZE // 8  # Each encrypted message is sent as a block of this size
        with open(f"RECV_FOLDER/{fileName}", "wb") as fd:
            while True:
                try:
                    encrypted_data = self.recv_fixed(block_size)
                    decrypted_data = rsa.decrypt(encrypted_data, self.privateKey)
                    if decrypted_data == b"<|EOF|>":  # End-of-file marker
                        break
                    fd.write(decrypted_data)
                    if end_to_end:
                        self.exchange_new_keys()
                except rsa.DecryptionError as e:
                    self.Logger.error(f"Decryption failed: {e}")
                    break
                except Exception as e:
                    self.Logger.error(f"Error receiving file: {e}")
                    break

        self.Logger.success(f"RECEIVED FILE: {fileName}")
    
    def close(self):
        self.connection.close()
        self.server_socket.close()
        self.Logger.warning("Connection closed")