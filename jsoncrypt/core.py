"""
Module containing all functions in jsoncrypt.
"""
import base64
import json
import os
from pathlib import Path
from typing import Mapping, Union

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PathLike = Union[str, Path]

__all__ = [
    "can_access",
    "dump",
    "load",
]


def genkey(password: Union[bytes, str], salt: bytes) -> bytes:
    """
    Generate a key given a password and salt.

    :param password:
    :param salt:

    """
    if isinstance(password, str):
        password = password.encode()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key


def gensalt(length: int = 16) -> bytes:
    """
    Generate a salt. Default length is 16 bytes.

    :param length: length of the salt. Default length is 16 bytes.
    :returns the salt.
    """
    return os.urandom(length)


def can_access(path: PathLike, password: Union[bytes, str]) -> bool:
    """
    Check whether a password works on a file.

    :param path: File to check password with.
    :param password: Password.
    :returns whether the file is decryptable given a password.
    """
    with open(path, 'rb') as f:

        # Read encrypted data key.
        keylen = int.from_bytes(f.read(1), 'little')
        key_e = f.read(keylen)

        # Read salt.
        saltlen = int.from_bytes(f.read(1), 'little')
        salt = f.read(saltlen)

    # Generate a login cipher derived from the stored salt and supplied password.
    login_key = genkey(password, salt)
    login_cipher = Fernet(login_key)

    # Decrypt encrypted data key with login cipher, and use it to create a data cipher.
    try:
        login_cipher.decrypt(key_e)
        return True
    except InvalidToken:
        return False


def dump(
    path: PathLike,
    password: Union[bytes, str],
    data: Mapping,
) -> None:
    """
    Store a JSON-serializable dictionary as a password-encrypted file.
    
    The first byte stores the length of the key, which is then used to
    read the key. Then the next byte is the length of the salt, which is
    then used to load the salt. The remaining bytes are the encrypted data.
    """

    # Check that we can access the file.
    path = Path(path)
    if path.exists() and not can_access(path, password):
        raise PermissionError("Invalid password for '{path}'")

    # Get/generate the login key (and salt).
    salt = gensalt()
    key = genkey(password, salt)

    # Encrypt the data key using login info.
    cipher = Fernet(key)
    key_e = cipher.encrypt(key)

    keylen = len(key_e)
    if keylen > 255:
        raise ValueError("encrypted login key too long (max 255 bytes). Reduce"
                         "length of salt and/or password."
                         )

    # Serialize and encrypt the data.
    bts = json.dumps(data).encode()
    bts_e = cipher.encrypt(bts)

    # Write to file.
    with open(path, "wb") as f:

        # Store encrypted data key.
        f.write(keylen.to_bytes(1, "little"))
        f.write(key_e)

        # Store salt.
        f.write(len(salt).to_bytes(1, "little"))
        f.write(salt)

        # Store encrypted data.
        f.write(bts_e)


def load(path: PathLike, password: Union[bytes, str]) -> Mapping:
    """
    Load encrypted, JSON-serialized data.

    :param path: path to encrypted file.
    :param password: password to try with file.
    """

    with open(path, 'rb') as f:

        # Read encrypted data key.
        keylen = int.from_bytes(f.read(1), 'little')
        key_e = f.read(keylen)

        # Read salt.
        saltlen = int.from_bytes(f.read(1), 'little')
        salt = f.read(saltlen)

        # Read remaining data.
        bts_e = f.read()

    # Generate a login cipher derived from the stored salt and supplied password.
    login_key = genkey(password, salt)
    login_cipher = Fernet(login_key)

    # Decrypt encrypted data key with login cipher, and use it to create
    # a data cipher.
    try:
        data_key = login_cipher.decrypt(key_e)
    except InvalidToken:
        raise PermissionError("Invalid password for '{path}'")

    data_cipher = Fernet(data_key)

    # Decrypt and decode remaining bytes.
    bts = data_cipher.decrypt(bts_e)
    txt = bts.decode()
    data = json.loads(txt)

    return data
