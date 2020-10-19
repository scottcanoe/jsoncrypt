"""

"""
import base64
import getpass
import json
import os
from pathlib import Path
import shutil
from typing import Optional, Union



def get_temp_dir(recreate: bool = False):
    
    p = Path(__file__).parent / "tmp"
    if p.exists() and recreate:
        shutil.rmtree(p)
    p.mkdir(exist_ok=True)
    return p
        


def test_dump_and_load():
    
    from jsoncrypt import dump, load
    
    datadir = get_temp_dir(recreate=True)
    
    test_password = "password123"    
    
    a = {
        "domain" : "DOMAIN",
        "url" : "www.example.com",
        "username" : "fred",
        "password" : "abc123LOL",
    }
    
    
    dump(datadir / 'a', test_password, a)
    b = load(datadir / 'a', test_password)
    
    dump(datadir / 'b', test_password, b)
    c = load(datadir / 'b', test_password)
    
    assert a == b == c




