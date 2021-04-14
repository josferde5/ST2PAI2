import utils
import socket
import random
import errno

import database
from exceptions import DiffieHellmanError
import logging
import reports

logger = logging.getLogger(__name__)

buffer_size = 16384


def key_agreement(server_socket, received_info):
    data = received_info.split(',')
    w = random.randint(1, int(data[1]) - 1)
    dh = pow(int(data[3]), w, int(data[1]))
    b = pow(int(data[2]), w, int(data[1]))
    nonce = utils.generate_nonce()
    mac_b = utils.message_hmac(data[3], str(dh), nonce)
    server_socket.sendall(bytes(f'{str(b)},{str(mac_b)},{nonce}', 'utf-8'))

    try:
        data = server_socket.recv(buffer_size)
        received_info = str(data, 'utf-8').split(',')
    except socket.error as e:
        if e.errno == errno.ECONNABORTED:
            print("SERVER INFO: Connection aborted by the client. Maybe a problem with Diffie-Hellman key agreement?")
            return None

    mac_a = utils.message_hmac(str(b), str(dh), received_info[1])
    if not mac_a == received_info[0] or database.exists_nonce(received_info[1]):
        print(
            "SERVER INFO: the MAC received does not match with the one obtained in the server or NONCE wasn't unique. Aborting connection.")
        raise DiffieHellmanError(
            'The MAC received does not match with the one obtained in the or NONCE was not unique.')
    else:
        database.insert_nonce(received_info[1])
        key_hex = format(dh, 'x')
        print(f"SERVER INFO: the key is {key_hex}")
        return key_hex


def tcpip_server(s_socket):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with server_socket:
        server_addr = ('localhost', s_socket)
        server_socket.bind(server_addr)
        server_socket.listen(1)
        print('SERVER INFO: Server up, waiting for a connection.')
        connection, client_address = server_socket.accept()
        print('SERVER INFO: received connection from', client_address)
        with connection:
            while True:
                data = connection.recv(buffer_size)
                if not data:
                    continue

                received_info = str(data, 'utf-8')
                decoded = received_info.split(',')
                if decoded[0] == 'END':
                    break
                elif decoded[0] == 'KEYAGREEMENT':
                    print(f"SERVER INFO: establishing key agreement with Diffie-Hellman")
                    try:
                        key = key_agreement(connection, received_info)
                        if not key:
                            break
                    except DiffieHellmanError:
                        break
                else:
                    print("SERVER INFO: Received from client: " + received_info)
                    if decoded[1] == utils.message_hmac(decoded[0], key, decoded[2]) and not database.exists_nonce(
                            decoded[2]):
                        database.insert_nonce(decoded[2])
                        result = 'Correct message integrity.'
                        print('SERVER INFO: ' + result)
                    elif decoded[1] == utils.message_hmac(decoded[0], key, decoded[2]) and database.exists_nonce(
                            decoded[2]):
                        reports.update_logs(decoded[0], decoded[1], decoded[2], key, 'Duplicate nonce')
                        result = 'A reply attack has been detected.'
                        print('SERVER WARN: ' + result)
                    elif decoded[1] != utils.message_hmac(decoded[0], key, decoded[2]):
                        reports.update_logs(decoded[0], decoded[1], decoded[2], key, 'Modified message content')
                        result = 'Integrity void, message modified or treated.'
                        print('SERVER WARN: ' + result)

                    connection.send(bytes(result, 'utf-8'))
            print("SERVER INFO: Closing server.")
