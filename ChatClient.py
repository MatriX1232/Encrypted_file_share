import socket
from log import Logger
import os
import rsa
from time import sleep
from math import ceil
from ENV import *


class ChatClient:
    def __init__(self, ip: str = 'localhost', port: int = 25565):
        self.Logger = Logger('CLIENT')
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ip = ip
        self.port = port
        self.client_socket.connect((ip, port))
        self.Logger.info(f"Connected to {ip}:{port}")
        self.exchange_new_keys()
        # publicKey, privateKey = rsa.newkeys(KEY_SIZE)
        # self.publicKey = publicKey
        # self.privateKey = privateKey
        # self.Logger.warning(f"Private key: {self.publicKey}")
        # self.otherPublicKey = None
        
        # try:
        #     self.Logger.info("Sending public key")
        #     self.client_socket.send(self.publicKey.save_pkcs1())
        #     self.Logger.info("Public key sent")
        #     self.Logger.info("Waiting for public key")
        #     received_key = self.client_socket.recv(len(self.publicKey.save_pkcs1()))
        #     if received_key:
        #         self.otherPublicKey = rsa.PublicKey.load_pkcs1(received_key)
        #         self.Logger.info(f"Public key received: {self.otherPublicKey}")
        #     else:
        #         self.Logger.error("Failed to receive public key from server")
        # except Exception as e:
        #     self.Logger.error(f"Error receiving public key: {e}")


    def exchange_new_keys(self):
        # Generate new keys
        publicKey, privateKey = rsa.newkeys(KEY_SIZE)
        self.publicKey = publicKey
        self.privateKey = privateKey

        try:
            # self.Logger.info("Sending public key")
            self.client_socket.send(self.publicKey.save_pkcs1())
            # self.Logger.info("Public key sent")
            # self.Logger.info("Waiting for public key")
            received_key = self.client_socket.recv(len(self.publicKey.save_pkcs1()))
            if received_key:
                self.otherPublicKey = rsa.PublicKey.load_pkcs1(received_key)
                # self.Logger.info(f"Public key received: {self.otherPublicKey}")
                self.Logger.success("Exchanged new keys")
            else:
                self.Logger.error("Failed to receive public key from server")
        except Exception as e:
            self.Logger.error(f"Error receiving public key: {e}")

    
    
    def send_message(self, message):
        if self.otherPublicKey is None:
            self.Logger.error("Cannot send message, otherPublicKey is None")
            return
        try:
            if isinstance(message, str):
                # self.Logger.warning(f"Encoding | DATA: <{message}> | SIZE: {len(message)}")
                message = message.encode('utf-8')  # Ensure the message is in bytes
            encrypted = rsa.encrypt(bytes(message), self.otherPublicKey)
            self.client_socket.send(encrypted)
        except Exception as e:
            self.Logger.error(f"Error sending message: {e}")

    
    def send_file(self, path: str, end_to_end: bool = False) -> None:
        if end_to_end:
            self.Logger.warning("END-TO-END ENCRYPTION ENABLED")
        if not os.path.isfile(path=path):
            self.Logger.error("Given path does not exist or is not a file")
            return
        fileName = path.split("/")[-1]
        fileSize = os.path.getsize(path)
        self.Logger.info(f"SENDING FILE | File name: {fileName} | File size: {fileSize}")

        # Send file metadata
        self.send_message(fileName)
        self.send_message(str(fileSize))

        # Send file content
        i = 0
        n_iterations = ceil(fileSize / FILE_READ_SIZE) - 1
        with open(path, "rb") as fd:
            data = fd.read(FILE_READ_SIZE)
            while data:
                # Split data into chunks that fit within the RSA encryption limit
                for chunk_start in range(0, len(data), 117):  # 117 is the max chunk size for RSA encryption
                    chunk = data[chunk_start:chunk_start + 117]
                    self.send_message(chunk)
                self.Logger.success(f"[{i} / {n_iterations}] SENT")
                data = fd.read(FILE_READ_SIZE)
                i += 1
                if end_to_end:
                    self.exchange_new_keys()
            self.send_message(b'<|EOF|>')


    def receive_message(self):
        try:
            data = self.client_socket.recv(READ_SIZE)
            return rsa.decrypt(data, self.privateKey).decode('utf-8')
        except Exception as e:
            self.Logger.error(f"Error receiving message: {e}")
            return None

    def close(self):
        self.client_socket.close()
        self.Logger.warning("Connection closed")