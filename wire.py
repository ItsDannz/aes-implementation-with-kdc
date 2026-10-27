import hashlib
import hmac
import json
import secrets
import socket
import struct

from aes import cbc_decrypt, cbc_encrypt


MAX_PACKET_BYTES = 1024 * 1024
_DOMAIN = b"KI-KDC-v1\x00"
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


class ProtocolError(ValueError):
    pass

def _json_bytes(payload: dict) -> bytes:
    if not isinstance(payload, dict):
        raise ProtocolError("Payload harus berupa objek JSON.")
    
    try:
        result = json.dumps(
            payload, ensure_ascii=True, separators=(",", ":"), allow_nan=False
        ).encode("ascii")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ProtocolError("Payload tidak dapat diserialisasi sebagai JSON.") from exc
    
    if len(result) > MAX_PACKET_BYTES:
        raise ProtocolError("Payload melebihi batas 1 MiB.")
    
    return result


def _json_object(data: bytes) -> dict:
    def reject_constant(value):
        raise ValueError("Konstanta JSON tidak valid: " + value)

    try:
        payload = json.loads(data.decode("ascii"), parse_constant=reject_constant)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ProtocolError("Data bukan JSON ASCII yang valid.") from exc
    
    if not isinstance(payload, dict):
        raise ProtocolError("Payload harus berupa objek JSON.")
    
    return payload


def send_packet(sock: socket.socket, payload: dict) -> None:
    data = _json_bytes(payload)
    sock.sendall(struct.pack("!I", len(data)) + data)


def _recv_exact(sock: socket.socket, size: int, *, initial=False) -> bytes:
    chunks = []
    remaining = size

    while remaining:
        chunk = sock.recv(remaining)

        if not chunk:
            if initial and remaining == size:
                raise EOFError("Koneksi ditutup oleh peer.")

            raise ProtocolError("Koneksi terputus sebelum paket lengkap.")
        
        chunks.append(chunk)
        remaining -= len(chunk)

    return b"".join(chunks)


def recv_packet(sock: socket.socket) -> dict:
    header = _recv_exact(sock, 4, initial=True)
    (size,) = struct.unpack("!I", header)

    if size == 0 or size > MAX_PACKET_BYTES:
        raise ProtocolError("Panjang paket harus antara 1 byte dan 1 MiB.")
    
    return _json_object(_recv_exact(sock, size))


def _validate_key(key: bytes) -> None:
    if not isinstance(key, bytes) or len(key) != 16:
        raise ProtocolError("Kunci AES-128 harus berupa tepat 16 byte.")


def _context_bytes(context: str) -> bytes:
    if not isinstance(context, str) or not context or "\x00" in context:
        raise ProtocolError("Konteks harus berupa teks ASCII tanpa NUL dan tidak kosong.")
    
    try:
        return context.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ProtocolError("Konteks harus berupa teks ASCII.") from exc


def _mac(key: bytes, context: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    mac_key = hmac.new(key, b"KI-KDC-v1:mac", hashlib.sha256).digest()
    
    return hmac.new(
        mac_key, 
        _DOMAIN + context + b"\x00" + iv + ciphertext, 
        hashlib.sha256
    ).digest()

#
def protect(key: bytes, payload: dict, context: str) -> dict:
    _validate_key(key)
    context_data = _context_bytes(context)

    #dictionary data sesi
    plaintext = _json_bytes(payload)
    iv = secrets.token_bytes(16)
    ciphertext = cbc_encrypt(key, plaintext, iv)

    return {
        "iv": iv.hex(),
        "ciphertext": ciphertext.hex(),
        "tag": _mac(key, context_data, iv, ciphertext).hex(),
    }


def _hex_bytes(value, name: str, *, exact_bytes=None) -> bytes:
    if (
        not isinstance(value, str)
        or not value
        or len(value) % 2
        or not all(char in _HEX_DIGITS for char in value)
    ):
        raise ProtocolError(name + " harus berupa Hex yang valid.")
    
    if exact_bytes is not None and len(value) != 2 * exact_bytes:
        raise ProtocolError("Panjang " + name + " tidak valid.")
    
    if len(value) > 2 * MAX_PACKET_BYTES:
        raise ProtocolError(name + " terlalu panjang.")
    
    return bytes.fromhex(value)


def unprotect(key: bytes, envelope: dict, context: str) -> dict:
    _validate_key(key)
    context_data = _context_bytes(context)

    if not isinstance(envelope, dict) or set(envelope) != {"iv", "ciphertext", "tag"}:
        raise ProtocolError("Amplop harus berisi iv, ciphertext, dan tag saja.")
    
    iv = _hex_bytes(envelope["iv"], "IV", exact_bytes=16)
    
    ciphertext = _hex_bytes(envelope["ciphertext"], "Ciphertext")
    tag = _hex_bytes(envelope["tag"], "Tag", exact_bytes=32)
    
    if len(ciphertext) % 16:
        raise ProtocolError("Panjang ciphertext harus kelipatan 16 byte.")
    
    expected = _mac(key, context_data, iv, ciphertext)
    
    if not hmac.compare_digest(tag, expected):
        raise ProtocolError("Autentikasi pesan gagal: kunci, konteks, atau data berbeda.")
    
    try:
        plaintext = cbc_decrypt(key, ciphertext, iv)
    except ValueError as exc:
        raise ProtocolError("Ciphertext tidak dapat didekripsi.") from exc
    
    return _json_object(plaintext)
