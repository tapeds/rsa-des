import socket
import threading
from Crypto.PublicKey import RSA
from datetime import datetime
import json


class PublicKeyAuthority:
    def __init__(self, host='localhost', port=6000):
        self.host = host
        self.port = port
        self.keys_db = {}  # {client_id: {'key': key_str, 'timestamp': datetime}}
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.host, self.port))

    def start(self):
        self.socket.listen(5)
        print(f"Public Key Authority started on {self.host}:{self.port}")

        while True:
            client, address = self.socket.accept()
            client_thread = threading.Thread(
                target=self.handle_client, args=(client,))
            client_thread.start()

    def handle_client(self, client_socket):
        try:
            request = client_socket.recv(4096).decode('utf-8')
            request_data = json.loads(request)

            if request_data['action'] == 'register':
                response = self.register_key(
                    request_data['client_id'],
                    request_data['public_key']
                )
            elif request_data['action'] == 'get':
                response = self.get_key(request_data['client_id'])
            else:
                response = {'status': 'error', 'message': 'Invalid action'}

            client_socket.send(json.dumps(response).encode('utf-8'))

        except Exception as e:
            error_response = {'status': 'error', 'message': str(e)}
            client_socket.send(json.dumps(error_response).encode('utf-8'))
        finally:
            client_socket.close()

    def register_key(self, client_id, public_key):
        try:
            RSA.import_key(public_key)

            self.keys_db[client_id] = {
                'key': public_key,
                'timestamp': datetime.now().isoformat()
            }
            return {
                'status': 'success',
                'message': f'Public key registered for {client_id}'
            }
        except Exception as e:
            return {'status': 'error', 'message': f'Invalid key format: {str(e)}'}

    def get_key(self, client_id):
        if client_id in self.keys_db:
            return {
                'status': 'success',
                'public_key': self.keys_db[client_id]['key'],
                'timestamp': self.keys_db[client_id]['timestamp']
            }
        return {'status': 'error', 'message': 'Client ID not found'}


if __name__ == '__main__':
    pka = PublicKeyAuthority()
    pka.start()