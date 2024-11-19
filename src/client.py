import socket
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from algorithm import des_encrypt, des_decrypt


class SecureClient:
    def __init__(self, client_id, host=socket.gethostname(), port=5000, pka_host='localhost', pka_port=6000):
        self.host = host
        self.port = port
        self.pka_host = pka_host
        self.pka_port = pka_port
        self.client_id = client_id

    def register_with_pka(self):
        try:
            key = RSA.generate(2048)
            public_key = key.publickey().export_key().decode('utf-8')
            private_key = key.export_key().decode('utf-8')

            with open(f'client_{self.client_id}_private.pem', 'w') as f:
                f.write(private_key)

            pka_socket = socket.socket()
            pka_socket.connect((self.pka_host, self.pka_port))

            register_request = {
                'action': 'register',
                'client_id': self.client_id,
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

    def start(self):
        try:
            private_key = self.register_with_pka()

            client_socket = socket.socket()
            print(f"Connecting to server at {self.host}:{self.port}")
            client_socket.connect((self.host, self.port))
            print("Connected to server")

            client_socket.send(self.client_id.encode('utf-8'))

            encrypted_des_key = client_socket.recv(256)
            rsa_cipher = PKCS1_OAEP.new(private_key)
            des_key = rsa_cipher.decrypt(encrypted_des_key)
            print("DES key received and decrypted successfully")

            while True:
                try:
                    message = input("Message -> ")
                    if message.lower().strip() == 'bye':
                        break

                    ciphertext = des_encrypt(message, des_key)
                    client_socket.send(ciphertext.encode('utf-8'))

                    data = client_socket.recv(1024).decode('utf-8')
                    if not data:
                        break

                    plaintext = des_decrypt(data, des_key)
                    print(f'From server: {plaintext}')

                except Exception as e:
                    print(f"Error during communication: {e}")
                    break

        except Exception as e:
            print(f"Client error: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
            print("Connection closed")


if __name__ == '__main__':
    client_id = input("Enter client ID: ")
    client = SecureClient(client_id)
    client.start()
