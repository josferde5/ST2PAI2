import socket

import server
import hashlib
import io
import secrets
import logging
import config
import random

from exceptions import NewFileException

logger = logging.getLogger(__name__)
_hash_algorithm = {
    "SHA1": hashlib.sha1(),
    "SHA256": hashlib.sha256(),
    "SHA512": hashlib.sha512(),
    "SHA3_256": hashlib.sha3_256(),
    "SHA3_512": hashlib.sha3_512(),
    "BLAKE2B": hashlib.blake2b(digest_size=32),
    "BLAKE2S": hashlib.blake2s(digest_size=32)
}
buffer_size = 16384


def message_hmac(message, algorithm, key):
    return "mock"


def key_agreement(client_socket, prime, generator, algorithm):
    print(f"INFO: establishing key agreement with Diffie-Hellman")
    v = random.randint(1, prime-1)
    a = pow(generator, v, prime)
    client_socket.sendall(bytes(f'KEYAGREEMENT,{str(prime)},{str(generator)},{str(a)}', 'utf-8'))

    server_msg = client_socket.recv(buffer_size)
    received_info = str(server_msg, 'utf-8').split(',')
    dh = pow(int(received_info[0]), v, prime)
    mac_b = message_hmac(str(a), algorithm, str(dh))

    if not mac_b == received_info[1]:
        pass
    else:
        mac_a = message_hmac(received_info[0], algorithm, str(dh))
        client_socket.sendall(bytes(f'{str(mac_a)}', 'utf-8'))
        key_hex = format(dh, 'x')
        print(f"INFO: the key is {key_hex}")
        return key_hex


def tcpip_client(server_socket, algorithm, prime, generator):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    with client_socket:
        server_addr = ('localhost', server_socket)
        client_socket.connect(server_addr)
        print("INFO: Login client up and connected to login server.")
        key = key_agreement(client_socket, prime, generator, algorithm)

        while True:
            message = input("Please submit the message you want to send:")
            m_hmac = message_hmac(message, algorithm, key)
            client_socket.sendall(bytes(message+","+m_hmac, 'utf-8'))
            if message == 'END':
                break

        print('INFO: Closing connection.')


def generate_token():
    token = secrets.token_hex(32)
    return token


def get_hash_algorithm():
    c = config.Config()
    if c.hashing_algorithm == 'SHA1':
        return hashlib.sha1()
    elif c.hashing_algorithm == 'SHA256':
        return hashlib.sha256()
    elif c.hashing_algorithm == 'SHA512':
        return hashlib.sha512()
    elif c.hashing_algorithm == 'SHA3_256':
        return hashlib.sha3_256()
    elif c.hashing_algorithm == 'SHA3_512':
        return hashlib.sha3_512()
    elif c.hashing_algorithm == 'BLAKE2B':
        return hashlib.blake2b(digest_size=32)
    else:
        return hashlib.blake2s(digest_size=32)


def hash_file(file):
    file_hash = get_hash_algorithm()

    buffer_size = io.DEFAULT_BUFFER_SIZE

    with open(file, 'rb') as f:
        for chunk in iter(lambda: f.read(buffer_size), b""):
            file_hash.update(chunk)

    return file_hash.hexdigest()


def challenge(token, file_hash):
    token_int = int(token, base=16)
    hash_file_int = int(file_hash, base=16)

    if hash_file_int > token_int:
        return hash_file_int % token_int
    else:
        return token_int % hash_file_int


def check_file_integrity(filepath):
    token = generate_token()
    file_hash = hash_file(filepath)
    challenge_value = challenge(token, file_hash)
    mac_file = server.mac_function(file_hash, challenge_value)
    failed_reason = 'none'

    try:
        file_hash_server, mac_file_server, verification_hash = server.verify_integrity(filepath, file_hash, token)
        if verification_hash and not mac_file == mac_file_server:
            logger.warning(
                "The file %s is corrupted: the MAC obtained by the client is not the same as the one obtained by the server.",
                filepath)
            failed_reason = 'mac'
        elif not verification_hash:
            failed_reason = 'hash'
    except NewFileException:
        logger.info("The file %s was not registered in the server. It has been added successfully.", filepath)
        file_hash_server = None
        verification_hash = None

    return filepath, file_hash_server, verification_hash, failed_reason
