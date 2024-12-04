# https://www.nxp.com/docs/en/application-note/AN12196.pdf
from typing import Optional, Dict
from loguru import logger


from Cryptodome.Cipher import AES
from Cryptodome.Hash import CMAC


SV2 = "3CC300010080"


def my_cmac(key: bytes, msg: bytes = b"") -> bytes:
    cobj = CMAC.new(key, ciphermod=AES)
    if msg != b"":
        cobj.update(msg)
    return cobj.digest()


def decrypt_sun(sun: bytes, key: bytes) -> tuple[bytes, bytes]:
    ivbytes = b"\x00" * 16

    cipher = AES.new(key, AES.MODE_CBC, ivbytes)
    sun_plain = cipher.decrypt(sun)

    uid = sun_plain[1:8]
    counter = sun_plain[8:11]

    return uid, counter


def get_sun_mac(uid: bytes, counter: bytes, key: bytes) -> bytes:
    sv2prefix = bytes.fromhex(SV2)
    sv2bytes = sv2prefix + uid + counter

    mac1 = my_cmac(key, sv2bytes)
    mac2 = my_cmac(mac1)

    return mac2[1::2]

# Padding functions for AES ECB mode
def pad(data: bytes) -> bytes:
    pad_length = 16 - (len(data) % 16)
    return data + bytes([pad_length] * pad_length)

def unpad(data: bytes) -> bytes:
    pad_length = data[-1]
    if pad_length < 1 or pad_length > 16:
        raise ValueError("Invalid padding.")
    return data[:-pad_length]

# AES ECB Encryption and Decryption using Cryptodome
def encrypt_aes_ecb(key: bytes, data: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(data)
    return cipher.encrypt(padded_data)

def decrypt_aes_ecb(key: bytes, data: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(data)
    return unpad(decrypted)

def derive_keys(uid: str, version: int, issuer_key: bytes) -> Dict[str, str]:
    logger.debug(f"Deriving keys for UID: {uid}, Version: {version}")
    if len(uid) != 14:
        raise ValueError("UID must be exactly 7 bytes (14 hex characters).")
    try:
        uid_bytes = bytes.fromhex(uid)
    except ValueError:
        raise ValueError("UID must be a valid hex string.")
    version_bytes = version.to_bytes(4, 'little')
    HEX_PREFIX = '2d003f75'
    card_key_input = HEX_PREFIX + uid + version_bytes.hex()
    card_key = my_cmac(issuer_key, bytes.fromhex(card_key_input))
    card_key_hex = card_key.hex()
    k0 = my_cmac(card_key, bytes.fromhex('2d003f76')).hex()
    k1 = my_cmac(issuer_key, bytes.fromhex('2d003f77')).hex()
    k2 = my_cmac(card_key, bytes.fromhex('2d003f78')).hex()
    k3 = my_cmac(card_key, bytes.fromhex('2d003f79')).hex()
    k4 = my_cmac(card_key, bytes.fromhex('2d003f7a')).hex()
    ID = my_cmac(issuer_key, bytes.fromhex('2d003f7b') + uid_bytes).hex()

#    card_id = urlsafe_short_hash(uid.upper() + 'card_id').upper()
#    external_id = urlsafe_short_hash(uid.upper() + 'external_id').lower()
    card_name = uid.upper()
    return {
        'k0': k0,
        'k1': k1,
        'k2': k2,
        'k3': k3,
        'k4': k4,
        'ID': ID,
        'CardKey': card_key_hex,
        'card_id': ID.encode('utf-8'), #used by LNbits
        'external_id': ID.encode('utf-8'),
        'card_name': card_name, # defaults to just the UID
        'uid_bytes': uid_bytes,
    }
