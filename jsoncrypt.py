import base64
import getpass
import json
import os
from pathlib import Path
from typing import Union
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


PathLike = Union[str, Path]

__all__ = [
    "read",
    "write",
]

                        
def genkek(password: Union[bytes, str], salt: bytes) -> bytes:
    
    """
    Generate a key-encrypted key given a password and a salt.
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
    
    kek = base64.urlsafe_b64encode(kdf.derive(password))
    return kek


def password_prompt(confirm: bool = False) -> str:
    
    # Get password from user.
    pw = ""
    
    while pw.strip() == "":        
        pw = getpass.getpass("Enter password: ")

    if confirm:        
        pw_2 = getpass.getpass("Confirm password: ")
        if pw != pw_2:
            raise ValueError("Passwords do not match.")

    return pw




def write(path: PathLike,
          password: Union[bytes, str],
          data: dict,
          ) -> None:                

    
    salt = os.urandom(16)
    key = genkek(password, salt)    
    cipher = Fernet(key)
    kek = cipher.encrypt(key)

    keylen = len(kek)
    if keylen > 255:
        raise ValueError("password is too long")

    # Serialize the data.
    bts = json.dumps(data).encode()
    bts_e = cipher.encrypt(bts)

    # Write to file.
    with open(path, "wb") as f:
        f.write(keylen.to_bytes(1, "little"))
        f.write(salt)
        f.write(kek)
        f.write(bts_e)
    


def read(path: PathLike,
         password: Union[bytes, str],     
         ) -> None:
        
    with open(path, "rb") as f:
        keylen = int.from_bytes(f.read(1), 'little')
        salt = f.read(16)
        key_e = f.read(keylen)
        bts_e = f.read()
        
    login_key = genkek(password, salt)
    key = Fernet(login_key).decrypt(key_e)
    out = Fernet(key).decrypt(bts_e)
    out = out.decode()
    
    out = json.loads(out)
    return out


def test_read_and_write():
    
    a = {
        "domain" : "DOMAIN",
        "url" : "www.example.com",
        "username" : "fred",
        "password" : "abc123LOL",
    }
    
    write('a', 'skcpu', a)
    b = read('a', 'skcpu')
    
    write('b', 'skcpu', b)
    c = read('b', 'skcpu')
    
    assert a == b == c
        
    os.remove('a')
    os.remove('b')


