import hashlib
import hmac
import os
import socket
import random

from exceptions import NewFileException
from datetime import datetime as dt
import client
import logging
import config

logger = logging.getLogger(__name__)
_hash_table = {}
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


def message_hmac(message, algorithm, key):
    return "mock"


def key_agreement(server_socket, received_info, algorithm):
    data = received_info.split(',')
    w = random.randint(1, int(data[1]) - 1)
    dh = pow(int(data[3]), w, int(data[1]))
    b = pow(int(data[2]), w, int(data[1]))
    mac_b = message_hmac(data[3], algorithm, str(dh))
    server_socket.sendall(bytes(f'{str(b)},{str(mac_b)}', 'utf-8'))

    data = server_socket.recv(buffer_size)
    received_info = str(data, 'utf-8')

    mac_a = message_hmac(received_info, algorithm, str(dh))
    if not mac_a == received_info:
        pass
    else:
        key_hex = format(dh, 'x')
        print(f"INFO: the key is {key_hex}")
        return key_hex


def tcpip_server(s_socket, algorithm, key):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with server_socket:
        server_addr = ('localhost', s_socket)
        server_socket.bind(server_addr)
        server_socket.listen(1)
        print('INFO: Login server up, waiting for a connection.')
        connection, client_address = server_socket.accept()
        print('INFO: received connection from', client_address)
        with connection:
            while True:
                data = connection.recv(buffer_size)
                if not data:
                    continue

                received_info = str(data, 'utf-8')
                decoded = received_info.split(',')
                if decoded[0] == 'END':
                    break
                elif decoded[0] == ('KEYAGREEMENT'):
                    print(f"INFO: key agreement with Diffie-Hellman")
                    key = key_agreement(connection, received_info, algorithm)
                else:
                    print("INFO: Received from client: " + received_info)

                    if decoded[1] == client.message_hmac(data, algorithm, key):
                        print("INFO: Correct message integrity.")
                    else:
                        print("WARN: Integrity void, message modified or treated.")
            print("INFO: Closing server.")


def register_analysis_time():
    global datetime
    datetime = dt.now().strftime("%m/%d/%Y %H:%M:%S")


def store_files(path: str):
    for root, dirs, filenames in os.walk(path):
        for filename in filenames:
            full_path = os.path.join(root, filename)
            store_file(full_path)


def store_file(full_path):
    hash_hex = client.hash_file(full_path)
    _hash_table[full_path] = (hash_hex, datetime)


def mac_function(hash_string, challenge):
    c = config.Config()
    msg_bytes = bytes(hash_string, encoding='UTF-8')
    challenge_bytes = challenge.to_bytes(32, byteorder="big")
    digester = hmac.new(challenge_bytes, msg_bytes, _hash_algorithm.get(c.hashing_algorithm, hashlib.blake2s))
    return digester.hexdigest()


def verify_integrity(filepath, file_hash, token):
    try:
        file_hash_stored, previous_dt = _hash_table[filepath]
        _hash_table[filepath] = (file_hash_stored, datetime)
    except KeyError:
        store_file(filepath)
        raise NewFileException("")
    verification_hash = file_hash == file_hash_stored
    mac_file = None
    if verification_hash:
        challenge = client.challenge(token, file_hash_stored)
        mac_file = mac_function(file_hash, challenge)
    else:
        logger.warning(
            "The file %s is corrupted: the hash sent by the client is not the same as the one obtained by the server.",
            filepath)
    return file_hash_stored, mac_file, verification_hash


def check_deleted_files():
    keys_to_delete = []
    for k, v in _hash_table.items():
        if not v[1] == datetime:
            logger.warning(
                "The file %s has been deleted or is not found.",
                k)
            keys_to_delete.append(k)

    for k in keys_to_delete:
        del _hash_table[k]

    return keys_to_delete
