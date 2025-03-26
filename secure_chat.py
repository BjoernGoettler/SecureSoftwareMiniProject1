import socket
import threading
import base64
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class SecureChat:
    def __init__(self, is_server=False, host='localhost', port=8000):
        self.is_server = is_server
        self.host = host
        self.port = port
        self.session_key = None
        self.connection = None

        # Generate RSA key pair
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        self.peer_public_key = None

    def start(self):
        if self.is_server:
            self._start_server()
        else:
            self._start_client()

    def _start_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.host, self.port))
        server.listen(1)
        print(f"Server listening on {self.host}:{self.port}")

        self.connection, address = server.accept()
        print(f"Connection from {address}")

        # Exchange public keys
        self._exchange_keys()

        # Generate and send session key
        self._generate_session_key()
        self._send_session_key()

        # Start message threads
        self._start_message_threads()

    def _start_client(self):
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection.connect((self.host, self.port))
        print(f"Connected to {self.host}:{self.port}")

        # Exchange public keys
        self._exchange_keys()

        # Receive session key
        self._receive_session_key()

        # Start message threads
        self._start_message_threads()

    def _exchange_keys(self):
        # Serialize public key to PEM format
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Send public key
        self.connection.send(pem)

        # Receive peer's public key
        peer_pem = self.connection.recv(2048)
        self.peer_public_key = serialization.load_pem_public_key(peer_pem)

        print("Public keys exchanged successfully")

    def _generate_session_key(self):
        # Generate a random 256-bit (32-byte) session key
        self.session_key = os.urandom(32)
        print("Session key generated")

    def _send_session_key(self):
        # Encrypt session key with peer's public key
        encrypted_key = self.peer_public_key.encrypt(
            self.session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Send encrypted session key
        self.connection.send(encrypted_key)
        print("Session key sent")

    def _receive_session_key(self):
        # Receive encrypted session key
        encrypted_key = self.connection.recv(2048)

        # Decrypt session key with private key
        self.session_key = self.private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("Session key received")

    def _encrypt_message(self, message):
        # Generate a random IV
        iv = os.urandom(16)

        # Create an encryptor
        cipher = Cipher(algorithms.AES(self.session_key), modes.CFB(iv))
        encryptor = cipher.encryptor()

        # Encrypt the message
        ciphertext = encryptor.update(message.encode()) + encryptor.finalize()

        # Combine IV and ciphertext and encode in base64
        encrypted_data = base64.b64encode(iv + ciphertext).decode('utf-8')
        return encrypted_data

    def _decrypt_message(self, encrypted_data):
        # Decode base64
        raw_data = base64.b64decode(encrypted_data.encode('utf-8'))

        # Extract IV and ciphertext
        iv = raw_data[:16]
        ciphertext = raw_data[16:]

        # Create a decryptor
        cipher = Cipher(algorithms.AES(self.session_key), modes.CFB(iv))
        decryptor = cipher.decryptor()

        # Decrypt the message
        message = decryptor.update(ciphertext) + decryptor.finalize()
        return message.decode('utf-8')

    def _send_messages(self):
        try:
            while True:
                message = input("You: ")
                if message.lower() == 'exit':
                    break

                encrypted_message = self._encrypt_message(message)
                self.connection.send(encrypted_message.encode('utf-8'))
        except Exception as e:
            print(f"Error sending message: {e}")
        finally:
            self.connection.close()

    def _receive_messages(self):
        try:
            while True:
                encrypted_message = self.connection.recv(4096).decode('utf-8')
                if not encrypted_message:
                    break

                message = self._decrypt_message(encrypted_message)
                print(f"\nPeer: {message}")
                print("You: ", end='', flush=True)
        except Exception as e:
            print(f"Error receiving message: {e}")

    def _start_message_threads(self):
        # Start threads for sending and receiving messages
        threading.Thread(target=self._send_messages, daemon=True).start()
        threading.Thread(target=self._receive_messages).start()


# Example usage:
if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == 'server':
        chat = SecureChat(is_server=True)
    else:
        chat = SecureChat(is_server=False)

    chat.start()