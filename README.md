| Nama | NRP | Kelas |
| --- | --- | --- |
| Hazza Danta Hermandanu | 5025241117 | B |

Program ini mengimplementasikan distribusi key melalui Key Distribution Center (KDC), kemudian menggunakan key sesi tersebut untuk komunikasi dua arah antara Alice dan Bob. Inti AES-128, key expansion, mode CBC, padding, dan pertukaran lima langkah KDC ditulis menggunakan Python.

<br><br>

## Gambaran Program

### 1.1. Entitas yang digunakan

| Entitas | Tugas |
| --- | --- |
| KDC | Menyimpan key client dan membuat key session. |
| Alice | Menjalankan participant, meminta atau menerima sesi, serta mengirim dan menerima pesan. |
| Bob | Menjalankan participant dengan fitur yang sama seperti Alice. |

### 1.2. Symbol

| Simbol atau field | Fungsi |
| --- | --- |
| `Ka` | Key Alice dengan KDC |
| `Kb` | Key Bob dengan KDC |
| `Ks`| Key session yang dibuat KDC dan diberikan kepada Alice dan Bob |
| `N1` | Nonce dari initiator untuk mencocokkan respon KDC dengan request yang sedang ditunggu |
| `N2` | challenge random dari peer. Initiator menjawab dengan `N2 - 1` |
| `session_id` | identity sesi yang mengikat tiket, challenge-response, dan pesan chat |
| `iv` | Nilai awal CBC dengan panjang 16 byte dan digenerate setiap pemanggilan `protect()` |
| `tag` | Hasil HMAC-SHA256 untuk memeriksa keutuhan data dan konteks pesan |
| `seq` | Urutan pesan untuk setiap pengiriman dalam satu session |

### 1.3. Format data

- Key (Ka & Kb): tepat 16 karakter ASCII cetak
- Key session (Ks): 16 karakter ASCII acak dari KDC, lalu diubah menjadi bytes ketika dipakai AES
- Pesan chat: 1 - 16.384 karakter ASCII
- Ciphertext, IV, dan tag: direpresentasikan sebagai teks Hex dalam paket JSON
- Ukuran blok AES: 16 byte

### 1.4. Architecture

#### 1.4.1. Algortima KDC
<img width="696" height="429" alt="image" src="https://github.com/user-attachments/assets/11a90fd6-241b-45e4-a4d3-5973ee4a4ef7" /><br>
Arsitektur ini melibatkan tiga entitas, yaitu Alice sebagai initiator, Bob sebagai responder, dan Key Distribution Center (KDC) sebagai pembuat serta pembagi session key. Sebelum komunikasi dimulai, Alice dan KDC sudah memiliki key jangka panjang Ka, sedangkan Bob dan KDC memiliki Kb.
Pada langkah pertama, Alice mengirimkan identitas Alice, identitas Bob, dan nonce N1 kepada KDC. KDC kemudian membuat session key Ks dan mengirimkan dua paket kepada Alice. Paket pertama dienkripsi menggunakan Ka dan berisi Ks, kedua identitas, serta N1. Paket kedua merupakan tiket untuk Bob, berisi Ks dan identitas Alice, yang dienkripsi menggunakan Kb. Alice memeriksa N1 pada paket pertama, kemudian meneruskan tiket kepada Bob.
Setelah membuka tiket menggunakan Kb, Bob memperoleh Ks dan mengirimkan tantangan berupa nonce N2 yang dienkripsi menggunakan Ks. Alice menjawab dengan mengirimkan hasil fungsi f(N2) menggunakan key yang sama. Pada program ini, fungsi tersebut berupa N2 − 1. Bob memeriksa jawaban untuk memastikan bahwa pihak yang berkomunikasi dengannya menguasai Ks. Setelah proses selesai, Alice dan Bob menggunakan Ks untuk komunikasi AES dua arah.
<br><br>

#### 1.4.2. Struktur Utama AES
<img width="724" height="677" alt="image" src="https://github.com/user-attachments/assets/2dd028f8-6c57-4aca-a264-94e7946d45f1" /><br>
AES memproses satu blok plaintext sepanjang 16 byte atau 128 bit. Byte tersebut disusun menjadi matriks state berukuran 4 × 4, kemudian mengalami transformasi awal dan sejumlah round hingga menghasilkan ciphertext sepanjang 16 byte.
Pada AES-128, key berukuran 16 byte dan proses enkripsi menggunakan 10 round. Transformasi awal berupa AddRoundKey menggunakan round key ke-0. Round 1–9 menjalankan SubBytes, ShiftRows, MixColumns, dan AddRoundKey. Round ke-10 menjalankan tiga transformasi karena tidak menggunakan MixColumns. Bagian key expansion menyiapkan round key yang diperlukan pada setiap tahap.
<br><br>

#### 1.4.3. Enkrisi & Dekripsi Dalam AES
<img width="799" height="677" alt="image" src="https://github.com/user-attachments/assets/1276c836-9bf7-4795-98e0-19d29aa3e5a0" /><br>
Bagian kiri memperlihatkan proses perubahan plaintext menjadi ciphertext. Proses dimulai dengan AddRoundKey, dilanjutkan sembilan round dengan empat transformasi, kemudian satu round terakhir tanpa MixColumns.
Bagian kanan menunjukkan proses dekripsi yang dibaca dari bawah ke atas dimana ciphertext menjadi masukan, sedangkan plaintext di bagian atas merupakan hasil akhirnya. Dekripsi menggunakan inverse ShiftRows, inverse SubBytes, AddRoundKey, dan inverse MixColumns. Round key digunakan dalam urutan terbalik, dimulai dari round key ke-10 sampai round key ke-0.
<br><br>

##### 1.4.3.1. Substitute Bytes
<img width="999" height="659" alt="image" src="https://github.com/user-attachments/assets/d509c747-ab48-4386-9eb8-4248b0fb71f1" /><br>
SubBytes mengganti nilai setiap byte pada state menggunakan tabel substitusi yang disebut S-box. Setiap byte menjadi indeks untuk memperoleh nilai penggantinya dari tabel tersebut.
Transformasi ini mengubah nilai byte, sementara posisinya dalam state tetap sama. Seluruh 16 byte mengalami substitusi secara independen.
<br><br>

##### 1.4.3.2. Shift Rows
<img width="1128" height="663" alt="image" src="https://github.com/user-attachments/assets/aee09b50-8fc7-415d-8d72-cb907f276965" /><br>
ShiftRows menggeser posisi byte pada setiap baris state secara melingkar ke kiri. Baris pertama tidak digeser, baris kedua digeser satu posisi, baris ketiga dua posisi, dan baris keempat tiga posisi.
Pergeseran melingkar berarti byte yang melewati ujung kiri akan masuk kembali dari ujung kanan. Operasi ini mempertahankan nilai setiap byte, tetapi mengubah susunannya. Dengan demikian, byte yang sebelumnya berada dalam satu kolom tersebar ke kolom lain sebelum diproses oleh MixColumns.
<br><br>

##### 1.4.3.3. Mix Columns
<img width="1152" height="663" alt="image" src="https://github.com/user-attachments/assets/7b1a77e7-8964-4923-9039-9b5ce7b40726" /><br>
MixColumns mengolah setiap kolom state menggunakan perkalian dengan matriks konstanta AES. Setiap byte keluaran diperoleh dari gabungan keempat byte pada kolom masukan. Perhitungannya dilakukan dalam GF(2^8), dengan XOR sebagai operasi penjumlahannya.
Matriks enkripsi menggunakan konstanta 02, 03, dan 01, dengan baris pertama 02 03 01 01. Hasil transformasinya tetap berupa state 4 × 4 byte. Untuk dekripsi, inverse MixColumns menggunakan matriks berbeda dengan konstanta Hex 0E, 0B, 0D, dan 09, yang setara dengan desimal 14, 11, 13, dan 9.
<br><br>

##### 1.4.3.4. Round Key
<img width="1152" height="663" alt="image" src="https://github.com/user-attachments/assets/8b68a641-c44f-466a-b83d-b1e4343759a8" /><br>
AddRoundKey menggabungkan state dengan round key menggunakan operasi XOR pada byte yang bersesuaian. Setiap round key berukuran 16 byte, sehingga seluruh byte state memperoleh pasangan byte key.
Tanda tambah pada diagram menyatakan XOR. Operasi ini memasukkan pengaruh key ke dalam proses enkripsi. AddRoundKey juga digunakan saat dekripsi karena melakukan XOR dua kali dengan nilai key yang sama akan mengembalikan nilai semula.
<br><br>

#### 1.4.4. Proses Single Round AES
<img width="1600" height="889" alt="image" src="https://github.com/user-attachments/assets/9fcac81a-08f7-4d21-9fc9-e5dfcd16cec8" /><br>
AES-128 menggunakan 11 round key, yaitu round key ke-0 untuk transformasi awal dan round key ke-1 sampai ke-10 untuk sepuluh round berikutnya. Setiap round key terdiri atas empat word, dengan satu word berukuran empat byte.
Key expansion menghasilkan total 44 word, dari w0 sampai w43. Transformasi awal memakai w0–w3, round pertama memakai w4–w7, dan round terakhir memakai w40–w43. Empat word pertama merupakan key asli. Pada enkripsi chat dalam program ini, key asli tersebut adalah session key Ks.
<br><br>

#### 1.4.5. Key Expand
<img width="1600" height="889" alt="image" src="https://github.com/user-attachments/assets/582cfd5f-7806-4eb6-90f4-07136ce4b2cc" /><br>
Key expansion mengexpand key asli menjadi rangkaian round key. Pada AES-128, key awal dibagi menjadi empat word, yaitu w0, w1, w2, dan w3.
Fungsi g memproses sebuah word melalui tiga tahap, yaitu RotWord untuk memutar urutan byte, SubWord untuk mengganti byte menggunakan S-box, dan XOR dengan Rcon. Hasilnya digunakan untuk membentuk word berikutnya, misalnya w4 = w0 XOR g(w3). Word selanjutnya dibentuk melalui XOR dengan word yang telah tersedia. Proses ini berlanjut hingga diperoleh 44 word.
Seluruh round key dihitung dari key asli yang sama, sehingga tidak diperlukan pembuatan key acak baru pada setiap round.
<br><br>

## Hubungan Antarfile

| File | Pembagian kerja |
| --- | --- |
| `aes.py` | Operasi AES-128, S-box, shift rows, mix columns, round key, CBC, dan padding |
| `wire.py` | Convert ke format JSON, batas paket TCP, enkripsi/dekripsi envelope, dan HMAC |
| `protocol.py` | Validasi identitas, key, nonce, sesi, plaintext, dan nomor langkah KDC |
| `kdc.py` | Server pembuat key session dan ticket |
| `participant.py` | Listener client, pembentukan sesi, challenge-response, chat, menu input |
| `alice.py` | Client dengan identitas `alice` |
| `bob.py` | Client dengan identitas `bob` |

<br><br>

## Pengujian
### Nyalakan KDC, Bob, dan Alice Serta Input Ka dan Kb 
Jalankan `python3 kdc.py --host 192.168.56.1 --port 9000 --ttl 1800` di device KDC
<img width="801" height="106" alt="image" src="https://github.com/user-attachments/assets/c3125586-64cd-44ed-b763-75cec4cfaa62" />

<br>

Jalankan `python3 bob.py --host 192.168.56.20 --port 9002 --kdc-ip 192.168.56.1 --peer-ip 192.168.56.10 --peer-port 9001` di device Bob
<img width="1226" height="234" alt="image" src="https://github.com/user-attachments/assets/a58e6346-c5ae-473c-8358-a3693e586a43" />

<br>

Jalankan `python3 alice.py --host 192.168.56.10 --port 9001 --kdc-ip 192.168.56.1 --peer-ip 192.168.56.20 --peer-port 9002` di device Alice
<img width="1210" height="278" alt="image" src="https://github.com/user-attachments/assets/30ac7429-f1c4-477e-b118-ba8fe7699f9d" />

<br>

### Alice Mencoba Connect
Alice menjalankan `/connect` dan alogritma di KDC akan dijalankan
<img width="1211" height="372" alt="image" src="https://github.com/user-attachments/assets/2114067e-79b9-49c1-87fa-309d070dd081" />

<br>

Jika Ka dan Challenge sesuai, Bob akan terhubung dengan Alice
<img width="1547" height="118" alt="image" src="https://github.com/user-attachments/assets/768eb28b-5caf-4283-b93b-4e99bda5f413" />

<br>

### Alice dan Bob Saling Mengirim Pesan
####Alice
<img width="1208" height="405" alt="image" src="https://github.com/user-attachments/assets/c6303ee7-4896-40f1-b3c5-fb85b4aec2a9" />

<br>

#### Bob
<img width="1550" height="290" alt="image" src="https://github.com/user-attachments/assets/9ad36b42-13e1-44c2-a5a6-9f51ce485407" />

<br>

### Pengujian dengan Wireshark
Masukkan filter `tcp.port == 9000 || tcp.port == 9001 || tcp.port == 9002`
<br>

### Alice Connect & Bob Respond
<img width="1570" height="483" alt="image" src="https://github.com/user-attachments/assets/2f5feec9-e5ab-4165-a55e-9f2fb2c36555" />

<br>

### Alice & Bob mengirim pesan
Alice mengirim pesan `halo bob`<br>
<img width="1570" height="65" alt="image" src="https://github.com/user-attachments/assets/6c6f0753-5746-462e-bb0a-34664df30a2d" />

<br>




## Penjelasan Code
### 1. aes.py

File `aes.py` berisi implementasi AES-128 beserta CBC untuk mengenkripsi data yang lebih panjang dari satu blok. AES-128 memakai key 16 byte dan mengolah blok 16 byte melalui initial AddRoundKey serta 10 round. File ini dipanggil oleh `wire.py` melalui `cbc_encrypt()` dan `cbc_decrypt()`.

#### 1.1. Konstanta dan representasi state

```python
BLOCK_SIZE = 16
SBOX, INV_SBOX = _make_sboxes()
```

- `BLOCK_SIZE` menetapkan ukuran blok AES, yaitu 16 byte atau 128 bit
- `SBOX` menyimpan hasil substitusi untuk enkripsi, sedangkan `INV_SBOX` menyimpan inversenya untuk dekripsi
- State disimpan sebagai list 16 angka dan dibaca sebagai matriks 4 × 4 dengan empat byte pertama merupakan kolom pertama

```text
List: [b0, b1, b2, b3, b4, ..., b15]

Matriks state:
b0  b4  b8   b12
b1  b5  b9   b13
b2  b6  b10  b14
b3  b7  b11  b15
```

Indeks elemen pada baris `row` dan kolom `column` adalah `4 * column + row`. State tetap berukuran 16 byte sepanjang transformasi AES.

#### 1.2. Fungsi `ascii_key()`

```python
def ascii_key(text: str) -> bytes:
    if not isinstance(text, str):
        raise TypeError("Key harus berupa teks.")

    if len(text) != BLOCK_SIZE or any(not 32 <= ord(char) <= 126 for char in text):
        raise ValueError("Key harus tepat 16 karakter ASCII cetak (kode 32..126).")

    return text.encode("ascii")
```

- Fungsi: memvalidasi key yang dimasukkan pengguna dan mengubah teks menjadi byte.
- Cara kerja: input harus berupa string, tepat 16 karakter, dan setiap karakter memiliki kode ASCII 32–126. Input yang tidak sesuai menghasilkan error.
- Hasil: `text.encode("ascii")`, yaitu key bertipe `bytes` yang dapat diproses AES

#### 1.3. Fungsi `_check_block()`

```python
def _check_block(value: bytes, name: str) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} harus berupa bytes.")

    if len(value) != BLOCK_SIZE:
        raise ValueError(f"{name} harus tepat 16 byte.")
```

- Fungsi: memastikan sebuah nilai berupa `bytes` sepanjang 16 byte
- Cara kerja: memeriksa tipe dan panjang string
- Penggunaan: memeriksa key, IV, dan input enkripsi/dekripsi satu blok. Jika valid, fungsi selesai tanpa mengembalikan data baru

#### 1.4. Fungsi `_gf_mul()`

```python
def _gf_mul(a: int, b: int) -> int:
    result = 0

    while b:
        if b & 1:
            result ^= a
        a = ((a << 1) ^ (0x11B if a & 0x80 else 0)) & 0xFF
        b >>= 1

    return result
```

- Fungsi: melakukan perkalian dua byte dalam `GF(2^8)` yang digunakan AES
- Cara kerja: bit-bit `b` menentukan kontribusi `a` yang digabung dengan XOR. Nilai `a` digeser untuk iterasi berikutnya. Ketika bit tertingginya aktif, hasil direduksi menggunakan polinomial AES `0x11B`. Mask `0xFF` menjaga agar hasil tetap satu byte
- Hasil: angka 0–255. Contoh `_gf_mul(0x57, 0x03)` menghasilkan `0xF9`
- Penggunaan: MixColumns, pembentukan S-box, dan pembaruan round constant. Operasi ini berbeda dari perkalian bilangan bulat biasa

#### 1.5. Fungsi `_gf_pow()`

```python
def _gf_pow(value: int, exponent: int) -> int:
    result = 1

    while exponent:
        if exponent & 1:
            result = _gf_mul(result, value)
        value = _gf_mul(value, value)
        exponent >>= 1

    return result
```

- Fungsi: menghitung pangkat dalam `GF(2^8)` menggunakan `_gf_mul()`
- Cara kerja: metode kuadrat dan kali membaca bit eksponen. Basis dikuadratkan setiap iterasi, sedangkan hasil dikalikan basis ketika bit eksponen aktif
- Penggunaan: `_make_sboxes()` menghitung `value^254` untuk memperoleh inverse perkalian byte yang tidak 0. Contohnya, invers `0x53` adalah `0xCA`, sehingga `_gf_mul(0x53, 0xCA)` menghasilkan `0x01`

#### 1.6. Fungsi `_rotate_byte_left()`

```python
return ((value << count) | (value >> (8 - count))) & 0xFF
```

- Fungsi: memutar susunan bit satu byte ke kiri
- Cara kerja: bit yang melewati sisi kiri ditempatkan kembali di sisi kanan. Hasil dibatasi menjadi 8 bit
- Penggunaan: transformasi affine saat membuat S-box
#### 1.7. Fungsi `_make_sboxes()`

```python
inv = _gf_pow(value, 254) if value else 0
substituted = inv ^ 0x63

for rotation in range(1, 5):
    substituted ^= _rotate_byte_left(inv, rotation)
```

- Fungsi: membuat tabel S-box dan inverse S-box secara manual untuk seluruh 256 kemungkinan byte
- Cara kerja: setiap byte dicari inverse perkaliannya, kemudian dilakukan transformasi affine berupa rotasi bit dan XOR. Hasil dimasukkan ke tabel maju dan kebalikannya
- Hasil: dua tuple yang masing-masing berisi 256 angka. Sebagai contoh, `SBOX[0x53]` bernilai `0xED`, sedangkan `INV_SBOX[0xED]` bernilai `0x53`

#### 1.8. Fungsi `_expand_key()`

```python
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
```

- Fungsi: mengexpand key awal menjadi 11 round key sepanjang 16 byte, dengan total 176 byte atau 44 word. Satu word berisi empat byte
- Cara kerja: empat byte terakhir dipakai sebagai word sementara. Pada setiap batas 16 byte, word mengalami RotWord, SubWord, dan XOR dengan `rcon`. Byte baru dibentuk melalui XOR dengan byte 16 posisi sebelumnya
- Hasil: tuple round key indeks 0–10. Indeks 0 adalah key awal untuk initial AddRoundKey, indeks 1–10 digunakan pada round berikutnya. Nilai awal `rcon` adalah `0x01`, lalu  menjadi `02`, `04`, sampai `36` untuk 10 tahap ekspansi

#### 1.9. Fungsi `_add_round_key()`

```python
return [value ^ key_byte for value, key_byte in zip(state, round_key)]
```

- Fungsi: menggabungkan state dengan round key melalui XOR
- Cara kerja: `zip()` memasangkan byte state dan byte key pada posisi yang sama. Setiap pasangan menghasilkan satu byte state baru
- Hasil: list 16 byte. Fungsi yang sama dipakai saat enkripsi dan dekripsi karena XOR dapat dibalik dengan melakukan XOR menggunakan key yang sama

#### 1.10. Fungsi `_shift_rows()`

```python
direction = -1 if inverse else 1
```

- Fungsi: menggeser posisi byte pada setiap baris state secara melingkar
- Cara kerja: untuk enkripsi, baris 0 tetap, baris 1 digeser satu posisi ke kiri, baris 2 dua posisi, dan baris 3 tiga posisi
- Hasil: susunan list 16 byte yang baru. Jika `inverse=True`, pergeseran dilakukan ke kanan untuk membalik ShiftRows

#### 1.11. Fungsi `_mix_columns()`

```python
for coefficient, value in zip(coefficients, values):
    mixed ^= _gf_mul(coefficient, value)
```

- Fungsi: mencampur empat byte dalam setiap kolom melalui perkalian matriks di `GF(2^8)`
- Cara kerja: setiap kolom diproses menggunakan seluruh baris matriks. Matriks enkripsi diawali baris `(2, 3, 1, 1)`, sedangkan inverse diawali `(14, 11, 13, 9)`
- Hasil: empat byte baru untuk setiap kolom, sehingga state tetap 16 byte

#### 1.12. Metode `AES128.__init__()`

```python
_check_block(key, "Key AES-128")
self._round_keys = _expand_key(key)
```

- Fungsi: menyiapkan objek AES ketika `AES128(key)` dibuat
- Cara kerja: memvalidasi key, lalu menghitung dan menyimpan round key
- Penggunaan: objek yang sama dapat mengenkripsi beberapa blok dengan kumpulan round key tersebut

#### 1.13. Metode `AES128.encrypt_block()`

```python
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
```

- Fungsi: mengenkripsi satu blok 16 byte
- Cara kerja: input diperiksa dan menjalani initial AddRoundKey. Selanjutnya round 1–9 menjalankan SubBytes melalui `SBOX`, ShiftRows, MixColumns, dan AddRoundKey. Round 10 menjalankan SubBytes, ShiftRows, dan AddRoundKey tanpa MixColumns
- Hasil: `bytes(state)` berupa ciphertext 16 byte

#### 1.14. Metode `AES128.decrypt_block()`

```python
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
```

- Fungsi: mengembalikan satu blok ciphertext menjadi blok plaintext
- Cara kerja: proses dimulai dengan round key ke-10. Perulangan berjalan dari indeks 9 ke 0 melalui inverse ShiftRows, inverse SubBytes, dan AddRoundKey. Inverse MixColumns dijalankan jika indeks bukan 0
- Hasil: plaintext 16 byte. Jika input berasal dari CBC, hasil metode ini akan di-XOR dengan IV atau ciphertext sebelumnya sebelum menjadi blok plaintext CBC

#### 1.15. Fungsi `_pad()`

```python
count = BLOCK_SIZE - len(plaintext) % BLOCK_SIZE
return plaintext + bytes([count]) * count
```

- Fungsi: menambahkan padding PKCS#7 agar panjang data menjadi kelipatan 16 byte
- Cara kerja: jumlah byte tambahan adalah 1–16, setiap byte tambahan berisi jumlah tersebut. Contohnya, data sepanjang 13 byte ditambah tiga byte `03`
- Hasil: plaintext berpading. Jika panjang awal sudah kelipatan 16, tetap ditambahkan satu blok berisi 16 byte `10` Hex agar padding dapat dihapus secara pasti

#### 1.16. Fungsi `_unpad()`

```python
count = padded[-1]
```

- Fungsi: memeriksa dan menghapus padding setelah dekripsi CBC
- Cara kerja: data harus tidak kosong dan panjangnya kelipatan 16. Byte terakhir menentukan jumlah padding, nilainya harus 1–16 dan seluruh byte padding harus cocok
- Hasil: `padded[:-count]`, yaitu plaintext tanpa padding. Padding yang tidak valid menghasilkan `ValueError`

#### 1.17. Fungsi `_xor_blocks()`

```python
return bytes(a ^ b for a, b in zip(left, right))
```

- Fungsi: melakukan XOR dua deretan byte pada posisi yang sama
- Penggunaan: operasi chaining dalam CBC, yaitu XOR dengan IV pada blok pertama dan dengan ciphertext sebelumnya pada blok berikutnya
- Hasil: objek `bytes`. Dalam alur CBC, kedua masukan sudah berupa blok 16 byte

#### 1.18. Fungsi `cbc_encrypt()`

```python
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
```

- Fungsi: mengenkripsi pesan menggunakan AES-CBC
- Cara kerja: membuat objek AES128, memeriksa IV, memastikan plaintext berupa byte, lalu menambahkan padding. Data diambil per 16 byte. Blok pertama di-XOR dengan IV sebelum masuk `encrypt_block()`, blok selanjutnya di-XOR dengan ciphertext sebelumnya
- Setiap pemanggilan `encrypt_block()` menjalankan initial AddRoundKey dan 10 round penuh. Satu blok diselesaikan sebelum blok berikutnya dikerjakan
- Ciphertext tiap blok dimasukkan melalui `extend()`, kemudian dikonversi menjadi `bytes` ketika dikembalikan
- Fungsi menerima IV dari caller. IV acak dibuat oleh `protect()` dalam `wire.py`, dan dikirim bersama ciphertext. Variasi IV membuat pesan yang sama dengan key yang sama dapat menghasilkan ciphertext berbeda
- Hasil: byte ciphertext gabungan

#### 1.19. Fungsi `cbc_decrypt()`

```python
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
```

- Fungsi: mendekripsi ciphertext CBC menggunakan key dan IV peernya
- Cara kerja: ciphertext harus berupa byte, tidak kosong, dan panjangnya kelipatan 16. Setiap blok didekripsi melalui `decrypt_block()`, lalu hasilnya di-XOR dengan IV untuk blok pertama atau ciphertext sebelumnya untuk blok berikutnya. Hasil ditambahkan dalam `bytearray()`
- Hasil: `_unpad()` menghapus padding, kemudian plaintext dikembalikan sebagai `bytes`

### 2. wire.py

File `wire.py` mengatur format paket jaringan serta perlindungan data sebelum dikirim. File ini menjadi penghubung antara komunikasi socket pada KDC/participant dan algoritma AES pada `aes.py`. Data disusun sebagai JSON ASCII, sedangkan IV, ciphertext, dan tag dituliskan sebagai Hex.

`MAX_PACKET_BYTES` membatasi satu JSON maksimal 1 MiB. `_DOMAIN` menjadi penanda protokol pada perhitungan HMAC, sedangkan `_HEX_DIGITS` berisi karakter yang diperbolehkan dalam representasi Hex.

#### 2.1. Class `ProtocolError`

```python
class ProtocolError(ValueError):
    pass
```

- Class ini menyediakan jenis error untuk paket, metadata, atau hasil pemeriksaan protokol yang tidak valid
- `pass` berarti class tidak menambahkan perilaku baru

#### 2.2. Fungsi `_json_bytes()`

```python
result = json.dumps(
    payload, ensure_ascii=True, separators=(",", ":"), allow_nan=False
).encode("ascii")
```

- Fungsi ini menerima dictionary dan menghasilkan data JSON dalam bentuk `bytes` ASCII
- `ensure_ascii=True` memastikan representasi JSON menggunakan ASCII. `separators` mengurangi spasi tambahan agar paket lebih ringkas, sedangkan `allow_nan=False` menolak nilai numerik nonstandar JSON seperti NaN
- Input selain dictionary, kegagalan serialisasi, dan hasil melebihi 1 MiB ditolak dengan `ProtocolError`
- Fungsi dipakai saat menyiapkan paket jaringan maupun plaintext JSON yang akan dienkripsi

#### 2.3. Fungsi `_json_object()` dan `reject_constant()`

```python
def reject_constant(value):
    raise ValueError("Konstanta JSON tidak valid: " + value)

payload = json.loads(data.decode("ascii"), parse_constant=reject_constant)
```

- `_json_object()` membalik proses `_json_bytes()`: byte ASCII dibaca sebagai JSON dan dikembalikan sebagai dictionary
- `reject_constant()` merupakan fungsi di dalam `_json_object()`. Fungsi ini diberikan kepada parser JSON untuk menolak konstanta seperti NaN dan Infinity
- Data yang bukan ASCII, JSON rusak, atau hasil JSON yang bukan dictionary akan menghasilkan `ProtocolError`
- Fungsi ini dipakai sesudah menerima paket dan sesudah dekripsi, karena keduanya menghasilkan byte yang perlu dibaca kembali sebagai objek data Python

#### 2.4. Fungsi `send_packet()`

```python
data = _json_bytes(payload)
sock.sendall(struct.pack("!I", len(data)) + data)
```

- Fungsi ini mengirim dictionary melalui socket TCP. Dictionary terlebih dahulu diserialisasi menjadi byte JSON
- `struct.pack("!I", len(data))` membuat header panjang berupa bilangan unsigned 4 byte dalam urutan byte jaringan, yaitu big-endian
- Paket yang dikirim memiliki susunan `[panjang JSON 4 byte][JSON]`
- `sendall()` mengirim seluruh buffer dan mengeluarkan error jika gagal

#### 2.5. Fungsi `_recv_exact()`

```python
while remaining:
    chunk = sock.recv(remaining)
    chunks.append(chunk)
    remaining -= len(chunk)
```

- Fungsi ini membaca sampai jumlah byte yang diminta terkumpul
- Potongan data dikumpulkan pada `chunks`, lalu digabungkan dengan `b"".join(chunks)` 
- Hasil `recv()` yang kosong diperiksa sebelum ditambahkan. Jika koneksi ditutup sebelum byte pertama header diterima dengan `initial=True`, fungsi mengeluarkan `EOFError` sebagai tanda penutupan koneksi.
- Jika koneksi berhenti setelah sebagian header atau isi paket diterima, fungsi mengeluarkan `ProtocolError`

#### 2.6. Fungsi `recv_packet()`

```python
header = _recv_exact(sock, 4, initial=True)
(size,) = struct.unpack("!I", header)
return _json_object(_recv_exact(sock, size))
```

- Fungsi ini membaca satu paket lengkap sesuai format yang dibuat `send_packet()`
- Empat byte pertama dibaca sebagai panjang JSON. Pada kode lengkap, panjang nol atau panjang melebihi 1 MiB ditolak sebelum isi paket dibaca
- `_recv_exact()` kemudian membaca sebanyak `size` byte, dan `_json_object()` mengubahnya menjadi dictionary

#### 2.7. Fungsi `_validate_key()`

```python
if not isinstance(key, bytes) or len(key) != 16:
    raise ProtocolError("Kunci AES-128 harus berupa tepat 16 byte.")
```

- Fungsi ini memastikan kunci yang diterima lapisan perlindungan berupa `bytes` sepanjang 16 byte
- Jika pemeriksaan berhasil, fungsi selesai tanpa mengembalikan nilai

#### 2.8. Fungsi `_context_bytes()`

```python
return context.encode("ascii")
```

- Fungsi ini memvalidasi label konteks dan mengubahnya menjadi byte ASCII. Konteks harus berupa string, tidak kosong, serta tidak mengandung karakter NUL
- Pengirim dan penerima memberikan label yang sama saat memanggil `protect()` dan `unprotect()`

#### 2.9. Fungsi `_mac()`

```python
mac_key = hmac.new(key, b"KI-KDC-v1:mac", hashlib.sha256).digest()
return hmac.new(
    mac_key, _DOMAIN + context + b"\x00" + iv + ciphertext, hashlib.sha256
).digest()
```

- Fungsi ini membuat tag HMAC-SHA256 untuk memeriksa keaslian dan keutuhan envelope
- Tahap pertama menurunkan key HMAC dari key yang diberikan dan label tetap `KI-KDC-v1:mac`, sehingga key HMAC berbeda dari key AES yang langsung digunakan untuk enkripsi
- Tahap berikutnya menghitung HMAC atas penanda protokol, konteks, pemisah NUL, IV, dan ciphertext. Perubahan pada komponen tersebut membuat tag hasil perhitungan berbeda
- Mengembalikan nilaiberupa 32 byte. HMAC dan SHA-256 menggunakan library Python `hmac` dan `hashlib`

#### 2.10. Fungsi `protect()`

```python
plaintext = _json_bytes(payload)
iv = secrets.token_bytes(16)
ciphertext = cbc_encrypt(key, plaintext, iv)
```

- Fungsi ini menerima key, dictionary payload, dan konteks. Setelah validasi, payload diubah menjadi byte JSON ASCII
- IV acak baru sepanjang 16 byte dibuat untuk setiap pemanggilan. IV menjadi pasangan XOR blok plaintext pertama pada CBC, sebelum hasilnya masuk ke algoritma AES
- `cbc_encrypt()` menjalankan padding, pembagian blok, dan enkripsi AES manual. Setelah itu, `_mac()` membuat tag dari IV, ciphertext, dan konteks
- Mengembalikan nilai berupa dictionary dengan tiga field: `iv`, `ciphertext`, dan `tag`. Ketiganya ditampilkan sebagai string Hex melalui `.hex()`

#### 2.11. Fungsi `_hex_bytes()`

```python
return bytes.fromhex(value)
```

- Fungsi ini memvalidasi representasi Hex sebelum mengubahnya kembali menjadi byte.
- Input harus berupa string tidak kosong, jumlah karakternya genap, dan seluruh karakternya termasuk digit Hex. Spasi tidak diperbolehkan oleh pemeriksaan ini.
- Parameter `exact_bytes` menetapkan ukuran yang harus dipenuhi jika diberikan. Karena satu byte ditulis memakai dua karakter Hex, panjang string dibandingkan dengan `2 * exact_bytes`.
- Fungsi juga menolak nilai yang terlalu panjang. `unprotect()` memakainya untuk membaca IV 16 byte, tag 32 byte, dan ciphertext.

#### 2.12. Fungsi `unprotect()`

```python
expected = _mac(key, context_data, iv, ciphertext)
if not hmac.compare_digest(tag, expected):
    raise ProtocolError("Autentikasi pesan gagal: kunci, konteks, atau data berbeda.")
```

- Fungsi ini menerima key, envelope, dan konteks, lalu memeriksa bahwa envelope hanya memiliki field `iv`, `ciphertext`, dan `tag`
- Nilai Hex diubah menjadi byte. IV dan tag harus memiliki ukuran yang benar, sedangkan ciphertext harus merupakan kelipatan 16 byte
- Tag dihitung ulang dan dibandingkan menggunakan `hmac.compare_digest()`. Pemeriksaan tag dilakukan sebelum dekripsi. Jika key, konteks, atau data berbeda, fungsi langsung menolak envelope
- Jika tag cocok, `cbc_decrypt()` mengembalikan plaintext byte dan memeriksa padding. `_json_object()` kemudian menghasilkan dictionary asli sebagai nilai return

### 3. protocol.py

File `protocol.py` berisi aturan bersama yang digunakan KDC dan participant: identitas, pembuatan nonce dan session key, pembacaan master key, serta pemeriksaan metadata. `IDENTITIES` membatasi peserta pada `alice` dan `bob`, `MAX_TEXT` membatasi pesan sampai 16.384 karakter, dan `CLOCK_SKEW = 30` memberi waktu pembuatan sesi sampai 30 detik ke depan.

#### 3.1. Fungsi `opposite()`

```python
return "bob" if name == "alice" else "alice"
```

- Fungsi ini menentukan identitas pasangan komunikasi. Alice mendapat pasangan Bob dan sebaliknya
- Sebelum mengembalikan nama pasangan, fungsi menolak identitas di luar `IDENTITIES`
- Fungsi ini tidak mencari perangkat pada jaringan

#### 3.2. Fungsi `nonce()`

```python
return secrets.token_hex(16)
```

- Fungsi ini menghasilkan 16 byte acak, yaitu 128 bit, lalu menyajikannya sebagai 32 karakter lowercase Hex
- Pada program, fungsi dipakai untuk N1 dari initiator sesi dan `session_id` yang dibuat KDC
- N2 dibuat terpisah di `participant.py` sebagai bilangan random positif, kemudian dikirim sebagai string desimal

#### 3.3. Fungsi `check_nonce()`

```python
if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{32}", value):
    raise ProtocolError("Format nonce tidak valid.")
```

- Fungsi ini memeriksa bahwa input berupa string 32 karakter Hex huruf kecil, lalu mengembalikan string tersebut
- Pencocokan N1 respond dengan N1 request dilakukan di `Participant.connect()`, sedangkan pemeriksaan penggunaan ulang tiket dilakukan oleh participant penerima

#### 3.4. Fungsi `new_session_key()`

```python
alphabet = string.ascii_letters + string.digits + string.punctuation
return "".join(secrets.choice(alphabet) for _ in range(16))
```

- Fungsi ini menghasilkan Ks berupa string berisi tepat 16 karakter ASCII cetak, dari kombinasi huruf, angka, dan tanda baca
- Pemilihan karakter menggunakan `secrets.choice()`. KDC memanggil fungsi ini ketika membuat sesi baru
- Ks yang sama dimasukkan ke paket untuk initiator dan ticket untuk peer. Setelah diterima, `check_session()` mengubah Ks tersebut menjadi byte untuk dipakai AES

#### 3.5. Fungsi `read_key_file()`

```python
text = Path(path).read_text(encoding="ascii")
return ascii_key(text)
```

- Fungsi ini membaca master key participant dari berkas ASCII
- Membuang satu newline penutup, kemudian satu carriage return penutup jika ada
- `ascii_key()` memeriksa 16 karakter ASCII cetak dan mengembalikan `bytes`

#### 3.6. Fungsi `prompt_key()`

```python
return ascii_key(getpass.getpass(f"{label} (16 karakter ASCII): "))
```

- Fungsi ini meminta master key melalui terminal menggunakan `getpass`, sehingga pada terminal normal karakter key tidak ditampilkan saat diketik
- Pemanggilan berada dalam perulangan `while True`. Jika `ascii_key()` menolak input, pesan kesalahan ditampilkan dan pengguna diminta memasukkan key lagi
- Hasilnya berupa key `bytes`. Key kemudian disimpan di memori oleh KDC atau participant pemanggil. Ka/Kb dimasukkan terpisah pada KDC dan client dengan nilai yang sama

#### 3.7. Fungsi `load_kdc_keys()`

```python
return {name: ascii_key(value[name]) for name in IDENTITIES}
```

- Fungsi ini membaca berkas JSON berisi pasangan master key milik KDC
- Objek JSON wajib memiliki tepat dua field, yaitu `alice` dan `bob`. Masing-masing nilainya diperiksa melalui `ascii_key()`
- Hasilnya dictionary dengan bentuk `{"alice": Ka_bytes, "bob": Kb_bytes}`. Dictionary tersebut diberikan kepada objek KDC untuk penyimpanan key di memori

#### 3.8. Fungsi `check_session()`

```python
required = {"ks", "id_a", "id_b", "session_id", "issued_at", "expires_at"}
return ascii_key(value["ks"])
```

- Fungsi ini memeriksa metadata sesi yang sudah dibuka melalui `unprotect()`. Seluruh field wajib harus tersedia, sedangkan field tambahan seperti N1 boleh tetap ada
- `id_a` dan `id_b` harus cocok dengan pasangan identitas yang diharapkan. `session_id` diperiksa formatnya menggunakan `check_nonce()`
- Waktu pembuatan dan kedaluwarsa harus berupa `int`, bukan boolean. Waktu penerbitan tidak boleh lebih dari 30 detik, durasi harus 1–3.600 detik, dan waktu kedaluwarsa harus belum terlewati
- Setelah seluruh pemeriksaan lolos, Ks divalidasi dan dikembalikan sebagai 16 byte melalui `ascii_key()`

#### 3.9. Fungsi `ascii_plaintext()`

```python
if any(not (32 <= ord(char) <= 126 or char == "\t") for char in text):
    raise ProtocolError("Pesan harus ASCII yang dapat dicetak (tanpa emoji/aksen).")
```

- Fungsi ini memastikan pesan berupa string tidak kosong dengan panjang maksimal 16.384 karakter
- Karakter yang diperbolehkan adalah ASCII cetak berkode 32–126 dan tab. Emoji, aksen, serta karakter kontrol lain ditolak

#### 3.10. Fungsi `expect_step()`

```python
if packet.get("step") != step or type(packet.get("step")) is not int:
    raise ProtocolError(f"Mengharapkan pesan langkah {step}.")
```

- Fungsi ini memastikan nomor langkah pesan sesuai dengan tahap handshake yang sedang dijalankan. Nilainya harus benar-benar bertipe `int`
- Jika field `type` berisi `error`, fungsi terlebih dahulu mengeluarkan `ProtocolError` bahwa client tujuan menolak permintaan
- Saat pemeriksaan berhasil, fungsi selesai tanpa mengembalikan nilai

#### 3.11. Fungsi `ciphertext_log()`

```python
return envelope["ciphertext"]
```

- Fungsi ini mengambil string ciphertext Hex dari envelope untuk ditampilkan pada log terminal

### 4. kdc.py

File ini berisi kelas `KeyDistributionCenter` dan fungsi `main()` untuk menjalankan server KDC. KDC menangani permintaan langkah 1 dan mengirim balasan langkah 2. Langkah 3 sampai 5 diteruskan langsung oleh Alice dan Bob.

#### 4.1. `KeyDistributionCenter.__init__(host, port, keys, ttl=300, log=print)`

```python
self.host, self.port, self.ttl = host, port, ttl
self.keys = {name: ascii_key(key.decode("ascii")) for name, key in keys.items()}
self._lock = threading.Lock()
self._stop = threading.Event()
```

- Menyiapkan alamat server, port, masa berlaku sesi, serta tempat penyimpanan key jangka panjang
- `keys` harus memuat tepat identitas `alice` dan `bob`, dengan key 16 byte yang lolos validasi ASCII
- `self.keys` merupakan dictionary di memori proses KDC. Nama peserta menjadi key dictionary, sedangkan nilainya adalah key kriptografi milik peserta tersebut
- `ttl` harus berada pada rentang 1 sampai# 1.600 detik. Nilai bawaan 300 detik berarti sesi diberi masa berlaku lima menit
- `_lock` mengatur akses ke dictionary key. `_stop` menjadi penanda penghentian server, sedangkan `_listener` dan `_thread` disiapkan untuk socket serta thread penerima koneksi

#### 4.2. `KeyDistributionCenter.start()`

```python
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.bind((self.host, self.port))
listener.listen(16)
listener.settimeout(0.5)
self._thread = threading.Thread(target=self._accept, daemon=True)
self._thread.start()
```

- Membuat socket TCP IPv4, bind ke alamat KDC, dan mulai listen koneksi
- `SO_REUSEADDR` untuk penggunaan ulang alamat socket
- Menjalankan `_accept()` di thread terpisah sehingga terminal KDC tetap bisa menerima perintah pengguna
- Jika persiapan socket gagal, socket ditutup dan error diteruskan kepada pemanggil. Jika berhasil, alamat listener dicetak melalui `log`

#### 4.3. `KeyDistributionCenter._accept()`

```python
while not self._stop.is_set():
    try:
        connection, address = self._listener.accept()
    except socket.timeout:
        continue
    except OSError:
        break
    threading.Thread(target=self._handle, args=(connection, address), daemon=True).start()
```

- Menunggu koneksi masuk selama KDC belum dihentikan
- `accept()` menghasilkan socket koneksi peserta dan alamat asal koneksinya
- Setiap koneksi ditangani `_handle()` pada thread tersendiri, sehingga listener dapat kembali menerima koneksi berikutnya
- Timeout hanya mengulang pemeriksaan. Error socket, misalnya listener ditutup saat `stop()`, menghentikan perulangan

#### 4.4. `KeyDistributionCenter._handle(connection, address)`

Potongan pembuatan data sesi:

```python
with self._lock:
    key_a, key_b = self.keys[id_a], self.keys[id_b]

issued = int(time.time())
common = {
    "ks": new_session_key(),
    "id_a": id_a,
    "id_b": id_b,
    "session_id": nonce(),
    "issued_at": issued,
    "expires_at": issued + self.ttl,
}
```

Fungsi ini menjalankan alur inti KDC:

1. Membaca request dengan `recv_packet()` dan memastikan request merupakan langkah 1 melalui `expect_step()`
2. Memeriksa bahwa identitas initiator dan responder berupa string, terdaftar, serta berbeda. Pemeriksaan tersebut memvalidasi isi identitas
3. Memeriksa format `n1` dengan `check_nonce()`
4. Mengambil kedua key jangka panjang saat memegang `_lock`, lalu melepas lock setelah nilainya diperoleh
5. Membuat satu `Ks` acak, satu `session_id`, waktu penerbitan, dan waktu kedaluwarsa
6. Mengenkripsi paket initiator dan tiket responder secara terpisah, lalu mengirim keduanya dalam langkah 2

Code pembuatan balasan:

```python
for_a = protect(key_a, {common, "n1": n1}, f"kdc-reply:{id_a}:{id_b}")
ticket = protect(key_b, common, f"ticket:{id_b}")
send_packet(connection, {"step": 2, "for_a": for_a, "ticket": ticket})
```

- `for_a` memuat data sesi dan salinan `N1`, dilindungi key jangka panjang initiator
- `ticket` memuat data sesi untuk responder, dilindungi key jangka panjang responder
- Kedua envelope memuat Ks yang sama, karena berasal dari dictionary `common` yang sama. Setiap pemanggilan `protect()` tetap membuat IV baru
- Ticket merupakan field tersendiri dalam balasan. Ticket tidak dimasukkan ke dalam plaintext `for_a`
- Initiator dapat membuka `for_a`, tetapi hanya meneruskan tiket tanpa membukanya. Responder membuka tiket dengan master key miliknya sendiri

Data `common` dibuat untuk request tersebut dan KDC tidak menyimpan objek `Session` chat. Setelah balasan dikirim, blok `with connection` menutup koneksi peserta–KDC. Jika validasi atau pemrosesan gagal, KDC mencatat penolakan dan mencoba mengirim paket error umum.

#### 4.5. `KeyDistributionCenter.set_key(name, key)`

```python
key = ascii_key(key.decode("ascii"))
with self._lock:
    self.keys[name] = key
```

- Memastikan identitas yang diubah terdaftar dan nilai key sesuai format ASCII
- Mengganti entri key client di memori KDC secara terkontrol menggunakan lock
- Dipakai oleh menu `/key alice` atau `/key bob` tanpa menjalankan ulang server

#### 4.6. `KeyDistributionCenter.stop()`

```python
self._stop.set()
if self._listener:
    self._listener.close()
if self._thread:
    self._thread.join(timeout=2)
```

- Mengatur penanda berhenti agar perulangan `_accept()` selesai
- Menutup listener sehingga KDC berhenti menerima koneksi baru
- Menunggu thread listener hingga dua detik

#### 4.7. `main()`

```python
keys = load_kdc_keys(args.keys_file) if args.keys_file else {
    name: prompt_key(f"Key {name}–KDC") for name in sorted(IDENTITIES)
}
server = KeyDistributionCenter(args.host, args.port, keys, args.ttl)
server.start()
```

- Membaca argumen CLI: alamat listener, port, TTL, file key, dan opsi tanpa console
- Jika `--keys-file` diberikan, key dibaca dari file JSON lokal. Jika tidak, pengguna memasukkan key Alice dan Bob melalui `prompt_key()`
- Membuat objek KDC dan mengaktifkan listener dengan `start()`
- Menjalankan menu `/key alice`, `/key bob`, dan `/quit`. Penggantian key melewati `prompt_key()` dan `set_key()`
- Jika `--no-console` aktif, server tetap berjalan tanpa menu. Opsi ini disediakan untuk pengujian otomatis
- Menggunakan `finally` untuk memanggil `stop()` saat program selesai, termasuk ketika pengguna menekan Ctrl+C

### 5. participant.py

File `participant.py` berisi proses yang digunakan bersama oleh Alice dan Bob, mulai dari membuka koneksi, menjalankan skenario distribusi key, mengirim pesan, sampai menutup sesi. Perbedaan keduanya ditentukan oleh nama peserta dan konfigurasi alamat yang diberikan. Dengan demikian, Alice dan Bob sama-sama dapat menjadi pemulai sesi maupun penerima koneksi.

#### 5.1. Dataclass `Session`

```python
@dataclass
class Session:
    connection: socket.socket
    key: bytes = field(repr=False)
    session_id: str
    id_a: str
    id_b: str
    expires_at: int
    send_sequence: int = 0
    receive_sequence: int = 0
```

`Session` merupakan tempat menyimpan informasi sesi yang sudah terbentuk. `@dataclass` membantu membuat constructor dan representasi objek berdasarkan atributnya.

- `connection` menyimpan socket yang dipakai peserta untuk berkomunikasi langsung
- `key` menyimpan Ks. `repr=False` menyembunyikan atribut ini dari representasi otomatis objek
- `session_id`, `id_a`, `id_b`, dan `expires_at` untuk bind koneksi pada sesi dan pasangan peserta yang benar.
- `send_sequence` dan `receive_sequence` merupakan penghitung terpisah untuk masing-masing arah komunikasi
- `send_lock` mengatur agar pengiriman melalui sesi yang sama dikerjakan bergantian, sedangkan event `closed` menandai sesi yang sudah ditutup. `default_factory` membuat lock dan event baru untuk setiap objek sesi

#### 5.2. Fungsi `Participant.__init__()`

```python
self.name, self.peer_name = name, opposite(name)
self.master_key = ascii_key(master_key.decode("ascii"))
self.inbox = queue.Queue()
self.connected = threading.Event()
```

Constructor ini menyiapkan identitas, alamat listener, alamat KDC, alamat peer, dan master key peserta. Jika namanya `alice`, master key yang dimiliki adalah Ka dn jika `bob`, master key-nya Kb. Key tersebut dimasukkan secara lokal dan divalidasi kembali sebagai 16 karakter ASCII.

`inbox` merupakan antrean pesan yang berhasil diterima, sementara `connected` dan `_stop` menyimpan tanda kesiapan sesi serta penghentian program. Constructor juga menyiapkan beberapa lock:

- `_key_lock` melindungi pembacaan atau penggantian master key
- `_session_lock` melindungi akses ke referensi sesi aktif
- `_handshake_lock` mencegah dua proses pembentukan sesi berjalan bersamaan

Dictionary `_used_tickets` menyimpan ID tiket yang pernah digunakan beserta kedaluwarsanya. Atribut sesi, listener, dan thread diawali dengan `None` .

#### 5.3. Property `session()`

```python
@property
def session(self):
    with self._session_lock:
        return self._session
```

Property ini mengambil referensi sesi aktif dengan perlindungan lock. Hasilnya berupa objek `Session` atau `None` jika belum ada sesi.

#### 5.4. Fungsi `start()`

```python
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.bind((self.host, self.port))
listener.listen(8)
listener.settimeout(0.5)
```

`start()` membuat listener TCP IPv4, bind ke alamat peserta, lalu menjalankan `_accept()` pada daemon thread. Karena listener menunggu di thread berbeda, menu terminal tetap dapat menerima input pengguna.

`SO_REUSEADDR` untuk penggunaan kembali alamat socket setelah program sebelumnya ditutup.

#### 5.5. Fungsi `_accept()`

```python
connection, address = self._listener.accept()
threading.Thread(
    target=self._respond,
    args=(connection, address),
    daemon=True
).start()
```

`_accept()` menunggu koneksi masuk selama `_stop` belum aktif. Setiap koneksi yang diterima diteruskan kepada `_respond()` melalui thread baru. Timeout membuat loop mencoba lagi, sedangkan error socket menghentikan loop. `accept()` bertugas menerima koneksi, pemeriksaan tiket dan challenge dilakukan oleh `_respond()`.

#### 5.6. Fungsi `_dial()`

```python
source = None if self.host == "0.0.0.0" else (self.host, 0)
return socket.create_connection(address, timeout=8, source_address=source)
```

`_dial()` membuka koneksi TCP keluar, baik ke KDC maupun ke peer. Jika `--host` berisi IP tertentu, IP tersebut juga digunakan sebagai alamat source koneksi. Angka port `0` meminta sistem operasi memilih port source yang tersedia. Jika host menggunakan `0.0.0.0`, pemilihan alamat source diserahkan kepada sistem operasi.

#### 5.7. Fungsi `_ensure_available()`

```python
if session is not None and session.expires_at <= time.time():
    self._dispose(session)
    session = None
```

Fungsi ini memastikan peserta dapat memulai atau menerima sesi baru. Program yang sudah dihentikan akan ditolak. Sesi lama yang kedaluwarsa dibersihkan melalui `_dispose()`. Jika masih ada sesi aktif, pengguna diminta menjalankan `/close` terlebih dahulu.

#### 5.8. Fungsi `_activate()`

```python
check_session(material, material["id_a"], material["id_b"])
session = Session(
    connection, key, material["session_id"],
    material["id_a"], material["id_b"], material["expires_at"],
)
```

`_activate()` memeriksa kembali material sesi, membuat objek `Session`, dan menyimpannya sebagai sesi aktif. Di dalam lock, fungsi memastikan belum ada sesi lain, menghapus timeout handshake menggunakan `settimeout(None)`, lalu mengaktifkan event `connected`. Setelah itu, `_receive()` dimulai pada thread baru agar pesan dapat diterima ketika pengguna sedang mengetik.

#### 5.9. Fungsi `connect()`

```python
id_a, id_b, n1 = self.name, self.peer_name, nonce()
request = {"step": 1, "id_a": id_a, "id_b": id_b, "n1": n1}
```

`connect()` dijalankan ketika pengguna mengetik `/connect`. Nama A dan B menunjukkan peran dalam sesi: jika Bob memulai, Bob menjadi A dan Alice menjadi B.

Proses yang dikerjakan fungsi ini adalah:

1. Mengambil `_handshake_lock` tanpa menunggu. Jika handshake lain sedang berjalan, operasi ditolak. `_ensure_available()` memastikan tidak ada sesi aktif
2. Membuat N1, mengambil salinan referensi master key, dan membuka koneksi ke KDC melalui `_dial()`
3. Mengirim langkah 1 berupa kedua identitas dan N1. Permintaan ini belum dienkripsi. Balasan dibaca sebelum koneksi KDC ditutup oleh blok `with`
4. Memastikan balasan adalah langkah 2, membuka `for_a` dengan master key sendiri melalui `unprotect()`, lalu menjalankan `check_session()`. N1 dari balasan juga harus sama dengan N1 yang dibuat sebelumnya
5. Menyimpan ticket untuk peer tanpa membukanya. Ticket dienkripsi dengan master key peer yang tidak dimiliki initiator
6. Membuka koneksi langsung ke peer dan mengirim tiket sebagai langkah# 1
7. Menerima langkah 4, membuka challenge dengan Ks, memeriksa ID sesi, serta memvalidasi N2 sebagai angka positif yang lebih kecil daripada `2128`
8. Mengenkripsi jawaban `N2 - 1` dengan Ks, mengirimnya sebagai langkah 5, lalu mengaktifkan sesi

```python
answer = protect(
    key,
    {"session_id": material["session_id"], "response": str(n2_number - 1)},
    f"response:{id_a}:{id_b}"
)
send_packet(connection, {"step": 5, "payload": answer})
```

`kdc-reply`, `challenge`, dan `response` membedakan tujuan penggunaan paket melalui pemeriksaan HMAC. Jika pembentukan sesi gagal, socket peer yang belum diaktifkan ditutup. Bagian `finally` melepas handshake lock. Jika berhasil, fungsi mengembalikan objek `Session`.

#### 5.10. Fungsi `_respond()`

```python
material = unprotect(master_key, ticket, f"ticket:{id_b}")
key = check_session(material, id_a, id_b)
```

`_respond()` menangani koneksi dari initiator. Responder tidak perlu mengetik `/connect`, listener akan memanggil fungsi ini secara otomatis ketika koneksi masuk.

Alurnya adalah:

1. Mengambil handshake lock, memasang timeout delapan detik, dan memastikan peserta tersedia
2. Menerima langkah 3 serta membuka ticket menggunakan master key sendiri. `check_session()` memeriksa peer identitas dan masa berlaku, lalu mengembalikan Ks dalam bentuk byte
3. Menghapus catatan tiket yang sudah kedaluwarsa dari `_used_tickets`. ID sesi yang masih tercatat ditolak sebagai penggunaan ulang ticket
4. Menandai tiket sebagai terpakai sebelum mengirim challenge. Jika handshake kemudian gagal, tiket tersebut tetap tercatat sampai kedaluwarsa
5. Membuat N2 acak, mengenkripsi ID sesi dan N2 dengan Ks, lalu mengirim langkah 2
6. Menerima langkah 5, membuka jawabannya dengan Ks, dan memastikan ID sesi cocok serta `response` tepat sama dengan `str(n2 - 1)`
7. Memeriksa masa berlaku sesi kembali, lalu memanggil `_activate()` yang juga melakukan pemeriksaan sesi

```python
n2 = secrets.randbelow(2128 - 1) + 1
```

N2 dibuat melalui `secrets` sebagai bilangan positif dalam rentang 128 bit dan dikirim sebagai string desimal

Jika terjadi error, fungsi menampilkan alasan dan mencoba mengirim pesan error umum. Socket ditutup jika sesi belum aktif, dan lock yang berhasil diambil selalu dilepas.

#### 5.11. Fungsi `_require_session()`

```python
if session is None or session.closed.is_set():
    raise ProtocolError("Belum ada sesi. Jalankan /connect atau tunggu peer.")
```

Fungsi ini mengambil sesi untuk pengiriman pesan. Sesi yang belum ada atau sudah ditutup ditolak. Jika kedaluwarsa, sesi dibersihkan dan pengguna diminta membentuk sesi baru. Jika seluruh pemeriksaan berhasil, objek sesi dikembalikan kepada pemanggil.

#### 5.12. Fungsi `_send_record()`

```python
payload = {
    "session_id": session.session_id,
    "sender": self.name, "receiver": self.peer_name,
    "seq": sequence, "kind": kind,
}
```

Fungsi ini mengirim record aplikasi, baik pesan `chat` maupun pemberitahuan `close`. Di dalam `send_lock`, fungsi memeriksa kondisi sesi, mengambil nomor urut berikutnya, dan menyusun payload. Teks ditambahkan hanya untuk jenis `chat`.

```python
envelope = protect(session.key, payload, f"chat:{self.name}:{self.peer_name}")
send_packet(session.connection, {"type": "data", "payload": envelope})
```

Payload dienkripsi menggunakan Ks, lalu dikirim melalui socket sesi. Konteks menyertakan arah pengiriman. Penghitung `send_sequence` diperbarui setelah pengiriman berhasil.

#### 5.13. Fungsi `send_text()`

```python
ascii_plaintext(text)
session = self._require_session()
self._send_record(session, "chat", text)
```

`send_text()` memvalidasi plaintext ASCII, mengambil sesi aktif, lalu menyerahkan pengiriman kepada `_send_record()`. Jika terjadi error pengiriman yang ditangani, sesi dibersihkan dan error diteruskan. Pesan asli juga dicetak pada terminal pengirim dari variabel lokal `text`.

#### 5.14. Fungsi `_receive()`

```python
value = unprotect(
    session.key, packet.get("payload"),
    f"chat:{self.peer_name}:{self.name}"
)
```

`_receive()` berjalan pada thread penerimaan selama sesi belum ditutup. Paket dibaca melalui `recv_packet()`, diperiksa tipenya, lalu dibuka menggunakan Ks melalui `unprotect()`. Fungsi tersebut memeriksa HMAC sebelum mendekripsi AES-CBC.

Setelah memperoleh plaintext, `_receive()` memastikan sesi belum kedaluwarsa, ID sesi cocok, pengirim dan penerima sesuai, serta nomor urut tepat satu lebih besar daripada penghitung penerimaan sebelumnya. Nomor urut yang berulang atau melompat ditolak.

Jika jenis pesan `close`, loop dihentikan. Jika `chat`, teks divalidasi sebagai ASCII, dimasukkan ke `inbox` sebagai pasangan `(nama_peer, teks)`, lalu ciphertext dan plaintext ditampilkan. Jenis lain ditolak. Bagian `finally` membersihkan sesi melalui `_dispose()`.

#### 5.15. Fungsi `_dispose()`

```python
session.closed.set()
session.connection.shutdown(socket.SHUT_RDWR)
session.connection.close()
```

Fungsi ini menandai sesi ditutup dan menghentikan komunikasi socket pada kedua arah. Error pada `shutdown()` ditangani karena koneksi bisa sudah terputus. Referensi sesi aktif kemudian diubah menjadi `None` dan tanda `connected` dibersihkan, hanya jika sesi yang ditutup masih merupakan sesi aktif yang sama.

#### 5.16. Fungsi `close_session()`

```python
self._send_record(session, "close")
self._dispose(session)
```

Jika sesi aktif tersedia, fungsi mencoba mengirim pemberitahuan penutupan yang juga dienkripsi dengan Ks. `/close` mengakhiri sesi tanpa menghentikan seluruh program atau mengubah master key.

#### 5.17. Fungsi `set_master_key()`

```python
self._ensure_available()
with self._key_lock:
    self.master_key = key
```

Fungsi memvalidasi master key baru, mencegah perubahan selama handshake, dan memastikan tidak ada sesi aktif. Key kemudian diganti di memori client. Pengguna harus mengganti entri client yang sama pada KDC secara terpisah agar nilainya cocok.

#### 5.18. Fungsi `status()`

```python
role = "initiator (A)" if session.id_a == self.name else "responder (B)"
```

`status()` mengembalikan teks keadaan peserta. Jika belum ada sesi, hasilnya memuat identitas dan alamat peer. Jika ada sesi, hasilnya memuat peran, ID sesi, dan sisa waktu berlaku yang dibatasi minimal nol. Key tidak ditampilkan. Fungsi ini hanya melaporkan keadaan, bukan timer yang otomatis membersihkan sesi kedaluwarsa.

#### 5.19. Fungsi `stop()`

```python
self._stop.set()
self.close_session()
```

`stop()` menandai penghentian program, menutup sesi aktif, menutup listener, dan menunggu thread penerimaan koneksi hingga dua detik. Berbeda dengan `/close`, fungsi ini juga menghentikan kesiapan program untuk menerima sesi baru.

#### 5.20. Fungsi `main(name)` dan Menu Program

```python
key = read_key_file(args.key_file) if args.key_file else prompt_key(f"Key {name}–KDC")
participant = Participant(...)
participant.start()
```

`main(name)` membaca argumen CLI, memuat master key dari berkas atau prompt, membuat objek peserta, dan membuka listener. `...` merangkum argumen konfigurasi yang diteruskan kepada constructor.

Argumen meliputi alamat listener, port, IP/port KDC, IP/port peer, `--key-file`, dan `--no-console`. Port default adalah 9001 untuk Alice, 9002 untuk Bob, dan 9000 untuk KDC. IP peer diberikan lewat konfigurasi.

Konstanta `HELP` menyimpan petunjuk menu. Input dipetakan sebagai berikut:

| Input | Proses yang dipanggil |
|---|---|
| `/connect` | `connect()` untuk membentuk sesi |
| `/status` | `status()` untuk melihat keadaan sesi |
| `/key` | `prompt_key()` dan `set_master_key()` setelah sesi ditutup |
| `/close` | `close_session()` |
| `/help` | Menampilkan konstanta `HELP` |
| `/quit` | Keluar dari loop menu |
| Teks ASCII biasa | `send_text()` |

Mode `--no-console` melewati menu dan membiarkan program menunggu, Error operasi ditampilkan tanpa langsung keluar dari seluruh loop. `KeyboardInterrupt` atau EOF mengakhiri program, dan blok `finally` memanggil `stop()` untuk membersihkan koneksi.

### 6. alice.py dan bob.py

#### 6.1. Import Fungsi `main()`

```python
from participant import main
```

Kedua file merupakan entry point kecil yang menggunakan implementasi bersama dalam `participant.py`.

#### 6.2. Menentukan Identitas Peserta

Pada `alice.py`:

```python
if __name__ == "__main__":
    main("alice")
```

Pada `bob.py`:

```python
if __name__ == "__main__":
    main("bob")
```

Guard `if __name__ == "__main__"` memastikan program dijalankan ketika file dieksekusi langsung. Parameter `"alice"` atau `"bob"` menentukan identitas, peer, port default, prompt key, dan label terminal.

<br><br>

## Referensi
1. https://nesoacademy.org
2. https://csrc.nist.gov/pubs/sp/800/38/a/final
