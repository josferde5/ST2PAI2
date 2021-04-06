import hashlib
import hmac
import os

from error import NewFileException
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
datetime = None


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
