import hashlib
import hmac
import secrets
import socket
import random
import errno

import database
from exceptions import DiffieHellmanError
import logging
import config

logger = logging.getLogger(__name__)
_hash_algorithm = {
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
    "SHA3_256": hashlib.sha3_256,
    "SHA3_512": hashlib.sha3_512,
    "BLAKE2B": hashlib.blake2b,
    "BLAKE2S": hashlib.blake2s
}
buffer_size = 16384


def generate_nonce():
    return secrets.token_hex(64)


def challenge(key, nonce):
    key_int = int(key, base=16)
    nonce_int = int(nonce, base=16)
    if nonce_int > key_int:
        return nonce_int % key_int
    else:
        return key_int % nonce_int


def message_hmac(message, key, nonce):
    c = config.Config()
    msg_bytes = bytes(message, encoding='UTF-8')
    challenge_bytes = challenge(key, nonce).to_bytes(200, byteorder="big")
    digester = hmac.new(challenge_bytes, msg_bytes, _hash_algorithm.get(c.hashing_algorithm, hashlib.blake2s))
    return digester.hexdigest()


def key_agreement(server_socket, received_info):
    data = received_info.split(',')
    w = random.randint(1, int(data[1]) - 1)
    dh = pow(int(data[3]), w, int(data[1]))
    b = pow(int(data[2]), w, int(data[1]))
    nonce = generate_nonce()
    mac_b = message_hmac(data[3], str(dh), nonce)
    server_socket.sendall(bytes(f'{str(b)},{str(mac_b)},{nonce}', 'utf-8'))

    try:
        data = server_socket.recv(buffer_size)
        received_info = str(data, 'utf-8').split(',')
    except socket.error as e:
        if e.errno == errno.ECONNABORTED:
            print("SERVER INFO: Connection aborted by the client. Maybe a problem with Diffie-Hellman key agreement?")
            return None

    mac_a = message_hmac(str(b), str(dh), received_info[1])
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

                    if decoded[1] == message_hmac(decoded[0], key, decoded[2]) and not database.exists_nonce(
                            decoded[2]):
                        database.insert_nonce(decoded[2])
                        print("SERVER INFO: Correct message integrity.")
                    else:
                        print("SERVER WARN: Integrity void, message modified or treated.")
            print("SERVER INFO: Closing server.")
