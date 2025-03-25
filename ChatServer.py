import socket
from log import Logger
from encryption import ChatEncryption
import os
import rsa

# In a real application, the master key needs to be securely exchanged.
# SHARED_MASTER_KEY = b'3%\xca\xff\xe5\x9f\x00\x0eK%\x99\xaa\xca\tU|\xcc\xf3\xc5:\xce\x15\xe0\x94\\\xcd\x15H\x1aL \xcc'  # Example for demonstration

SYNC_MESSAGE = b'<|SYNC|>'


class ChatServer:
    def __init__(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('localhost', 25565))
        self.server_socket.settimeout(5)
        self.Logger = Logger('SERVER')
        # self.encryption = ChatEncryption(SHARED_MASTER_KEY)
        publicKey, privateKey = rsa.newkeys(1024)
        self.publicKey = publicKey
        self.privateKey = privateKey
        self.otherPublicKey = None
        self.Logger.warning(f"Private key: {self.publicKey}")
        self.Logger.error(f"Length of public key: {len(self.publicKey.save_pkcs1())}")


    def start(self):
        self.server_socket.listen(1)
        try:
            self.connection, address = self.server_socket.accept()
            self.Logger.info(f"Connection from {address}")
            
            # Receive the public key from the client
            self.Logger.info("Waiting for public key")
            self.otherPublicKey = rsa.PublicKey.load_pkcs1(self.connection.recv(251))
            self.Logger.info(f"Public key received: {self.otherPublicKey}")
            
             # Send the public key to the client
            self.connection.send(self.publicKey.save_pkcs1())
            self.Logger.info("Public key sent")
        except Exception as e:
            self.Logger.error("No connection incoming")
            exit(0)


    def sync(self):
        while (self.connection.recv(len(SYNC_MESSAGE)) != SYNC_MESSAGE):
            pass
        self.connection.send(SYNC_MESSAGE)


    def send_message(self, message):
        if isinstance(message, str):
            message = message.encode('utf-8')  # Ensure the message is in bytes
        if self.otherPublicKey is None:
            self.Logger.error("Cannot send message, otherPublicKey is None")
            return
        try:
            encrypted = rsa.encrypt(message, self.otherPublicKey)
            self.connection.send(encrypted)
        except Exception as e:
            self.Logger.error(f"Error sending message: {e}")
    
    def receive_message(self):
        # Increase buffer size if needed.
        data = self.connection.recv(4096)
        # return self.encryption.decrypt(data)
        return rsa.decrypt(data, self.privateKey).decode('utf-8')
    
    def close(self):
        self.connection.close()
        self.server_socket.close()
        self.Logger.warning("Connection closed")