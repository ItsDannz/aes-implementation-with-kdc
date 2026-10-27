BLOCK_SIZE = 16

#cek asci & convert ke bytes
def ascii_key(text: str) -> bytes:
    if not isinstance(text, str):
        raise TypeError("Key harus berupa teks.")
    
    if len(text) != BLOCK_SIZE or any(not 32 <= ord(char) <= 126 for char in text):
        raise ValueError("Key harus tepat 16 karakter ASCII cetak (kode 32..126).")
    
    return text.encode("ascii")

#cek block size
def _check_block(value: bytes, name: str) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} harus berupa bytes.")
    
    if len(value) != BLOCK_SIZE:
        raise ValueError(f"{name} harus tepat 16 byte.")

#multiple
def _gf_mul(a: int, b: int) -> int:
    result = 0
    
    while b:
        if b & 1:
            result ^= a
        a = ((a << 1) ^ (0x11B if a & 0x80 else 0)) & 0xFF
        b >>= 1
    
    return result

#power
def _gf_pow(value: int, exponent: int) -> int:
    result = 1
    
    while exponent:
        if exponent & 1:
            result = _gf_mul(result, value)
        value = _gf_mul(value, value)
        exponent >>= 1
    
    return result

def _rotate_byte_left(value: int, count: int) -> int:
    return ((value << count) | (value >> (8 - count))) & 0xFF

#buat sbox & inverse sbox
def _make_sboxes() -> tuple[tuple[int, ...], tuple[int, ...]]:
    forward = []
    inverse = [0] * 256
    
    for value in range(256):
        inv = _gf_pow(value, 254) if value else 0
        substituted = inv ^ 0x63
        
        for rotation in range(1, 5):
            substituted ^= _rotate_byte_left(inv, rotation)
        
        forward.append(substituted)
        inverse[substituted] = value
    
    return tuple(forward), tuple(inverse)

SBOX, INV_SBOX = _make_sboxes()

#expand key setiap round
def _expand_key(key: bytes) -> tuple[bytes, ...]:
    expanded = list(key)
    rcon = 1
    
    while len(expanded) < 11 * BLOCK_SIZE:
        word = expanded[-4:]
    
        if len(expanded) % BLOCK_SIZE == 0:
            word = [SBOX[value] for value in word[1:] + word[:1]]
            word[0] ^= rcon
            rcon = _gf_mul(rcon, 2)
    
        for value in word:
            expanded.append(expanded[-BLOCK_SIZE] ^ value)
    
    return tuple(bytes(expanded[i:i + BLOCK_SIZE])
                 for i in range(0, len(expanded), BLOCK_SIZE))

#combine state dengan round key
def _add_round_key(state: list[int], round_key: bytes) -> list[int]:
    return [value ^ key_byte for value, key_byte in zip(state, round_key)]

#shift rows
def _shift_rows(state: list[int], inverse: bool = False) -> list[int]:
    direction = -1 if inverse else 1
    
    return [state[4 * ((column + direction * row) % 4) + row]
            for column in range(4) for row in range(4)]

#mix columns
def _mix_columns(state: list[int], inverse: bool = False) -> list[int]:
    matrix = (
        (14, 11, 13, 9), 
        (9, 14, 11, 13),
        (13, 9, 14, 11), 
        (11, 13, 9, 14)
    ) if inverse else (
        (2, 3, 1, 1), 
        (1, 2, 3, 1),
        (1, 1, 2, 3), 
        (3, 1, 1, 2)
    )
    
    result = []
    
    for column in range(4):
        values = state[4 * column:4 * column + 4]
        
        for coefficients in matrix:
            mixed = 0
            
            for coefficient, value in zip(coefficients, values):
                mixed ^= _gf_mul(coefficient, value)
            
            result.append(mixed)
    
    return result

#main algorithm
class AES128:
    #prepare AES
    def __init__(self, key: bytes):
        _check_block(key, "Key AES-128")
        self._round_keys = _expand_key(key)

    #encrypt block
    def encrypt_block(self, block: bytes) -> bytes:
        _check_block(block, "Blok plaintext")
        state = _add_round_key(
            list(block), 
            self._round_keys[0]
        )

        for round_number in range(1, 11):
            #subs bytes
            state = [SBOX[value] for value in state]
            
            #shift rows
            state = _shift_rows(state)           

            #round N
            if round_number != 10:                   
                state = _mix_columns(state)
            state = _add_round_key(state, self._round_keys[round_number])

        return bytes(state)

    #decrypt block
    def decrypt_block(self, block: bytes) -> bytes:
        _check_block(block, "Blok ciphertext")
        state = _add_round_key(list(block), self._round_keys[10])
        
        for round_number in range(9, -1, -1):
            #inverse shift rows
            state = _shift_rows(state, inverse=True)

            #inverse subs bytes
            state = [INV_SBOX[value] for value in state]  

            #round N
            state = _add_round_key(state, self._round_keys[round_number])
            if round_number != 0:
                state = _mix_columns(state, inverse=True)

        return bytes(state)

#padding
def _pad(plaintext: bytes) -> bytes:
    count = BLOCK_SIZE - len(plaintext) % BLOCK_SIZE
    
    return plaintext + bytes([count]) * count

#cek & delete padding
def _unpad(padded: bytes) -> bytes:
    if not padded or len(padded) % BLOCK_SIZE:
        raise ValueError("Padding PKCS#7 tidak valid.")
    
    count = padded[-1]
    
    if not 1 <= count <= BLOCK_SIZE or padded[-count:] != bytes([count]) * count:
        raise ValueError("Padding PKCS#7 tidak valid.")
    
    return padded[:-count]

#xor block
def _xor_blocks(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))

#encrypt message
def cbc_encrypt(key: bytes, plaintext: bytes, iv: bytes) -> bytes:
    cipher = AES128(key)

    _check_block(iv, "IV")

    if not isinstance(plaintext, bytes):
        raise TypeError("Plaintext harus berupa bytes.")

    padded = _pad(plaintext)
    previous = iv
    ciphertext = bytearray()

    for start in range(0, len(padded), BLOCK_SIZE):
        block = padded[start:start + BLOCK_SIZE]
        previous = cipher.encrypt_block(_xor_blocks(block, previous))
        ciphertext.extend(previous)
        
    return bytes(ciphertext)

#decrypt message
def cbc_decrypt(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    cipher = AES128(key)
    _check_block(iv, "IV")

    if not isinstance(ciphertext, bytes):
        raise TypeError("Ciphertext harus berupa bytes.")

    if not ciphertext or len(ciphertext) % BLOCK_SIZE:
        raise ValueError("Ciphertext harus tidak kosong dan kelipatan 16 byte.")
   
    previous = iv
    padded = bytearray()

    for start in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[start:start + BLOCK_SIZE]
        padded.extend(
            _xor_blocks(cipher.decrypt_block(block), 
            previous)
        )
        previous = block

    return _unpad(bytes(padded))