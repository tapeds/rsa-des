import socket

from algorithm import des_encrypt, des_decrypt

def client_program():
    host = socket.gethostname()  # as both code is running on same pc
    port = 5000  # socket server port number

    client_socket = socket.socket()  # instantiate
    client_socket.connect((host, port))  # connect to the server

    message = input(" -> ")  # take input

    ciphertext = des_encrypt(message)

    while message.lower().strip() != 'bye':
        client_socket.send(ciphertext.encode())  # send message
        data = client_socket.recv(1024).decode()  # receive response

        plaintext = des_decrypt(data)

        print('Received from server: ' + plaintext)  # show in terminal

        message = input(" -> ")  # again take input

    client_socket.close()  # close the connection


if __name__ == '__main__':
    client_program()
