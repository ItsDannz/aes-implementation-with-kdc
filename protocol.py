import getpass
import json
from pathlib import Path
import re
import secrets
import string
import time

from aes import ascii_key
from wire import ProtocolError

IDENTITIES = frozenset({"alice", "bob"})
MAX_TEXT = 16_384
CLOCK_SKEW = 30

def opposite(name):
    if name not in IDENTITIES:
        raise ValueError("Identitas harus alice atau bob.")
    
    return "bob" if name == "alice" else "alice"

def nonce():
    return secrets.token_hex(16)

def check_nonce(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{32}", value):
        raise ProtocolError("Format nonce tidak valid.")
    
    return value

def new_session_key():
    alphabet = string.ascii_letters + string.digits + string.punctuation
    
    return "".join(secrets.choice(alphabet) for _ in range(16))

def read_key_file(path):
    text = Path(path).read_text(encoding="ascii")
    
    if text.endswith("\n"):
        text = text[:-1]
    
    if text.endswith("\r"):
        text = text[:-1]
    
    return ascii_key(text)

def prompt_key(label):
    while True:
        try:
            return ascii_key(getpass.getpass(f"{label} (16 karakter ASCII): "))
        except ValueError as exc:
            print(f"Key ditolak: {exc}")

def load_kdc_keys(path):
    value = json.loads(Path(path).read_text(encoding="ascii"))
    
    if not isinstance(value, dict) or set(value) != IDENTITIES:
        raise ValueError('Berkas key KDC harus berisi objek dengan "alice" dan "bob".')
    
    return {name: ascii_key(value[name]) for name in IDENTITIES}

def check_session(value, id_a, id_b):
    required = {"ks", "id_a", "id_b", "session_id", "issued_at", "expires_at"}
    
    if not isinstance(value, dict) or not required <= value.keys():
        raise ProtocolError("Metadata sesi tidak lengkap.")
    
    if value["id_a"] != id_a or value["id_b"] != id_b:
        raise ProtocolError("Identitas pada sesi tidak sesuai.")
    
    check_nonce(value["session_id"])
    issued, expires = value["issued_at"], value["expires_at"]
    
    if type(issued) is not int or type(expires) is not int:
        raise ProtocolError("Waktu sesi harus berupa bilangan bulat.")
    
    now = time.time()
    
    if issued > now + CLOCK_SKEW or not 1 <= expires - issued <= 3600:
        raise ProtocolError("Rentang waktu sesi tidak valid; periksa jam perangkat.")
    
    if expires <= now:
        raise ProtocolError("Tiket/sesi sudah kedaluwarsa. Buat sesi baru.")
    
    try:
        return ascii_key(value["ks"])
    except (ValueError, TypeError) as exc:
        raise ProtocolError("Key sesi bukan 16 karakter ASCII.") from exc

def ascii_plaintext(text):
    if not isinstance(text, str) or not text or len(text) > MAX_TEXT:
        raise ProtocolError(f"Pesan harus berisi 1 sampai {MAX_TEXT} karakter.")
    
    if any(not (32 <= ord(char) <= 126 or char == "\t") for char in text):
        raise ProtocolError("Pesan harus ASCII yang dapat dicetak (tanpa emoji/aksen).")
    
    return text

def expect_step(packet, step):
    if packet.get("type") == "error":
        raise ProtocolError("Pihak tujuan menolak permintaan.")
    
    if packet.get("step") != step or type(packet.get("step")) is not int:
        raise ProtocolError(f"Mengharapkan pesan langkah {step}.")

def ciphertext_log(envelope):
    return envelope["ciphertext"]
