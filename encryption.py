# builtin imports
import os
import hashlib
from typing import Optional

# 3rd party imports
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV as AESGCMSIV



# constants
NONCE_LENGTH = 12
SALT_LENGTH = 16



def get_nonce() -> bytes:
    '''
    Returns a 12 byte (96 bit) nonce used in encryption.

    Should only be used once.
    '''

    return os.urandom(NONCE_LENGTH)



def get_salt() -> bytes:
    '''
    Returns a 16 byte (128 bit) salt used in encryption.
    '''

    return os.urandom(SALT_LENGTH)



def get_key(password: str, salt: Optional[bytes] = None) -> tuple[bytes, bytes]:
    '''
    Returns a key generated from a password and the salt used.
    '''

    if salt is None:
        salt = get_salt()

    key = hashlib.scrypt(
        password.encode('utf-8'),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=32
    )

    return key, salt



def encrypt(data: str | bytes, password: str, authentication: Optional[str] = None) -> bytes:
    '''
    Encrypts a string or bytes.

    `password` is the password used to encrypt. Should be the same for encryption and decryption.

    `authentication` is a string that is used to authenticate the data's integrity. Should be the same for encryption and decryption.
    '''

    # turn string into bytes
    if isinstance(data, str): data = data.encode('utf-8')

    # get cipher
    key, salt = get_key(password)

    cipher = AESGCMSIV(key)

    # encrypt data
    authentication_data = authentication.encode('utf-8') if authentication is not None else None

    nonce = get_nonce()

    cypher_text = cipher.encrypt(nonce, data, authentication_data)

    # add metadata for decryption to output
    return nonce + salt + cypher_text



def decrypt(cypher_text: bytes, password: str, authentication: Optional[str] = None) -> bytes:
    '''
    Decrypts bytes.

    `password` is the password used to decrypt. Should be the same for encryption and decryption.

    `authentication` is a string that is used to authenticate the data's integrity. Should be the same for encryption and decryption.
    '''

    # split off metadata
    nonce, salt, cypher_text = cypher_text[:NONCE_LENGTH], cypher_text[NONCE_LENGTH:NONCE_LENGTH + SALT_LENGTH], cypher_text[NONCE_LENGTH + SALT_LENGTH:]

    # get cipher
    key, _ = get_key(password, salt=salt)

    cipher = AESGCMSIV(key)

    # decrypt data
    authentication_data = authentication.encode('utf-8') if authentication is not None else None

    data = cipher.decrypt(nonce, cypher_text, authentication_data)

    return data

