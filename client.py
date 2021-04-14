import errno
import socket

import random

import config
import database
import utils
from exceptions import DiffieHellmanError
import ctypes

buffer_size = 16384


def key_agreement(client_socket):
    c = config.Config()
    print(f"CLIENT INFO: establishing key agreement with Diffie-Hellman")
    v = random.randint(1, c.prime - 1)
    a = pow(c.generator, v, c.prime)
    client_socket.sendall(bytes(f'KEYAGREEMENT,{str(c.prime)},{str(c.generator)},{str(a)}', 'utf-8'))

    server_msg = client_socket.recv(buffer_size)
    received_info = str(server_msg, 'utf-8').split(',')
    dh = pow(int(received_info[0]), v, c.prime)
    mac_b = utils.message_hmac(str(a), str(dh), received_info[2])

    if not mac_b == received_info[1] or database.exists_nonce(received_info[2]):
        raise DiffieHellmanError(
            'The MAC received does not match with the one obtained in the client or NONCE was reused')
    else:
        database.insert_nonce(received_info[2])
        nonce = utils.generate_nonce()
        mac_a = utils.message_hmac(received_info[0], str(dh), nonce)
        client_socket.sendall(bytes(f'{str(mac_a)},{nonce}', 'utf-8'))
        key_hex = format(dh, 'x')
        print(f"CLIENT INFO: the key is {key_hex}")
        return key_hex


def tcpip_client(server_socket):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    with client_socket:
        server_addr = ('localhost', server_socket)
        client_socket.connect(server_addr)
        print("CLIENT INFO: Client up and connected to login server.")
        try:
            key = key_agreement(client_socket)

            while True:
                try:
                    message = input("Please submit the message you want to send:")
                    nonce = utils.generate_nonce()
                    m_hmac = utils.message_hmac(message, key, nonce)
                    client_socket.sendall(bytes(message + "," + m_hmac + "," + nonce, 'utf-8'))
                    if message == 'END':
                        break
                    else:
                        while True:
                            data = client_socket.recv(buffer_size)
                            if not data:
                                continue
                            else:
                                print('CLIENT INFO: ' + str(data, 'utf-8'))
                                ctypes.windll.user32.MessageBoxW(0, str(data, 'utf-8'), 'Integrity in transmission', 0)
                                break
                except socket.error as e:
                    if e.errno == errno.ECONNABORTED:
                        print(
                            "CLIENT INFO: Connection aborted by the server. Maybe a problem with Diffie-Hellman key agreement?")
                        break
                    else:
                        raise e

        except DiffieHellmanError:
            print("CLIENT INFO: the MAC received does not match with the one obtained in the client. Aborting connection.")

        print('CLIENT INFO: Closing connection.')
