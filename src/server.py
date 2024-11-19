import socket
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from algorithm import des_encrypt, des_decrypt


class SecureServer:
    def __init__(self, host=socket.gethostname(), port=5000, pka_host='localhost', pka_port=6000):
        self.host = host
        self.port = port
        self.pka_host = pka_host
        self.pka_port = pka_port
        self.server_id = "server"

    def register_with_pka(self):
        try:
            key = RSA.generate(2048)
            public_key = key.publickey().export_key().decode('utf-8')
            private_key = key.export_key().decode('utf-8')

            with open('server_private.pem', 'w') as f:
                f.write(private_key)

            pka_socket = socket.socket()
            pka_socket.connect((self.pka_host, self.pka_port))

            register_request = {
                'action': 'register',
                'client_id': self.server_id,
                'public_key': public_key
            }

            pka_socket.send(json.dumps(register_request).encode('utf-8'))
            response = json.loads(pka_socket.recv(4096).decode('utf-8'))

            if response['status'] != 'success':
                raise Exception(
                    f"PKA registration failed: {response['message']}")

            pka_socket.close()
            return key

        except Exception as e:
            raise Exception(f"Failed to register with PKA: {str(e)}")

    def get_client_key(self, client_id):
        """Get client's public key from PKA"""
        try:
            pka_socket = socket.socket()
            pka_socket.connect((self.pka_host, self.pka_port))

            request = {
                'action': 'get',
                'client_id': client_id
            }

            pka_socket.send(json.dumps(request).encode('utf-8'))
            response = json.loads(pka_socket.recv(4096).decode('utf-8'))

            if response['status'] != 'success':
                raise Exception(
                    f"Failed to get client key: {response['message']}")

            pka_socket.close()
            return RSA.import_key(response['public_key'])

        except Exception as e:
            raise Exception(f"Failed to get client key from PKA: {str(e)}")

    def start(self):
        try:
            private_key = self.register_with_pka()

            des_key = get_random_bytes(8)

            server_socket = socket.socket()
            server_socket.bind((self.host, self.port))
            server_socket.listen(2)

            print(f"Server started on {self.host}:{self.port}")
            print("Waiting for client connection...")

            while True:
                conn, address = server_socket.accept()
                print(f"Connection established from: {address}")

                client_id = conn.recv(1024).decode('utf-8')
                print(f"Client identified as: {client_id}")

                client_public_key = self.get_client_key(client_id)

                rsa_cipher = PKCS1_OAEP.new(client_public_key)
                encrypted_des_key = rsa_cipher.encrypt(des_key)

                conn.send(encrypted_des_key)
                print("DES key sent to client")

                self.handle_client_communication(conn, des_key)

        except Exception as e:
            print(f"Server error: {e}")
        finally:
            try:
                server_socket.close()
            except:
                pass
            print("Server shutdown")

    def handle_client_communication(self, conn, des_key):
        try:
            while True:
                data = conn.recv(1024).decode('utf-8')
                if not data:
                    break

                plaintext = des_decrypt(data, des_key)
                print(f"From client: {plaintext}")

                message = input("Reply -> ")
                if message.lower().strip() == 'bye':
                    break

                ciphertext = des_encrypt(message, des_key)
                conn.send(ciphertext.encode('utf-8'))

        except Exception as e:
            print(f"Error during communication: {e}")
        finally:
            conn.close()


if __name__ == '__main__':
    server = SecureServer()
    server.start()
