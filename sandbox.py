"""

"""

import getpass

import os
from pathlib import Path
from typing import Optional, Union


from jsoncrypt import *


PathLike = Union[str, Path]



def password_prompt(confirm: bool = False) -> str:
    """
    Get a password from the user.
    """
    # Get password from user.
    pw = ""
    
    while pw.strip() == "":
        pw = getpass.getpass("Enter password: ")

    if confirm:
        pw_2 = getpass.getpass("Confirm password: ")
        if pw != pw_2:
            raise ValueError("Passwords do not match.")

    return pw

