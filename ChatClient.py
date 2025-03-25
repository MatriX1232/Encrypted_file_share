import socket
from log import Logger
from encryption import ChatEncryption
import os
import rsa


SYNC_MESSAGE = b'<|SYNC|>'

class ChatClient:
    def __init__(self, ip: str = 'localhost', port: int = 12345):
        self.Logger = Logger('CLIENT')
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ip = ip
        self.port = port
        self.client_socket.connect((ip, port))
        self.Logger.info(f"Connected to {ip}:{port}")
        publicKey, privateKey = rsa.newkeys(1024)
        self.publicKey = publicKey
        self.privateKey = privateKey
        self.Logger.warning(f"Private key: {self.publicKey}")
        self.otherPublicKey = None
        
        try:
            self.Logger.info("Sending public key")
            self.client_socket.send(self.publicKey.save_pkcs1())
            self.Logger.info("Public key sent")
            self.Logger.info("Waiting for public key")
            received_key = self.client_socket.recv(251)
            if received_key:
                self.otherPublicKey = rsa.PublicKey.load_pkcs1(received_key)
                self.Logger.info(f"Public key received: {self.otherPublicKey}")
            else:
                self.Logger.error("Failed to receive public key from server")
        except Exception as e:
            self.Logger.error(f"Error receiving public key: {e}")

    
    def sync(self):
        self.client_socket.send(SYNC_MESSAGE)
        while (self.client_socket.recv(len(SYNC_MESSAGE)) != SYNC_MESSAGE):
            pass

    
    
    def send_message(self, message):
        if self.otherPublicKey is None:
            self.Logger.error("Cannot send message, otherPublicKey is None")
            return
        try:
            if isinstance(message, str):
                message = message.encode('utf-8')  # Ensure the message is in bytes
            encrypted = rsa.encrypt(message, self.otherPublicKey)
            self.client_socket.send(encrypted)
        except Exception as e:
            self.Logger.error(f"Error sending message: {e}")

    def receive_message(self):
        try:
            data = self.client_socket.recv(4096)
            return rsa.decrypt(data, self.privateKey).decode('utf-8')
        except Exception as e:
            self.Logger.error(f"Error receiving message: {e}")
            return None

    def close(self):
        self.client_socket.close()
        self.Logger.warning("Connection closed")