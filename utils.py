import hashlib
import hmac
import secrets
import config

_hash_algorithm = {
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
    "SHA3_256": hashlib.sha3_256,
    "SHA3_512": hashlib.sha3_512,
    "BLAKE2B": hashlib.blake2b,
    "BLAKE2S": hashlib.blake2s
}


def challenge(key, nonce):
    key_int = int(key, base=16)
    nonce_int = int(nonce, base=16)
    if nonce_int > key_int:
        return nonce_int % key_int
    else:
        return key_int % nonce_int


def generate_nonce():
    return secrets.token_hex(64)


def message_hmac(message, key, nonce):
    c = config.Config()
    msg_bytes = bytes(message, encoding='UTF-8')
    challenge_bytes = challenge(key, nonce).to_bytes(200, byteorder="big")
    digester = hmac.new(challenge_bytes, msg_bytes, _hash_algorithm.get(c.hashing_algorithm, hashlib.blake2s))
    return digester.hexdigest()
