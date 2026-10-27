import argparse
from dataclasses import dataclass, field
import queue
import secrets
import socket
import threading
import time

from aes import ascii_key
from protocol import (
    ascii_plaintext, 
    check_session, 
    ciphertext_log, 
    expect_step, 
    nonce,
    opposite, 
    prompt_key, 
    read_key_file,
)
from wire import ProtocolError, protect, recv_packet, send_packet, unprotect


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
    send_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    closed: threading.Event = field(default_factory=threading.Event, repr=False)


class Participant:
    def __init__(self, name, host, port, kdc_address, peer_address, master_key, log=print):
        self.name, self.peer_name = name, opposite(name)
        self.host, self.port = host, port
        self.kdc_address, self.peer_address = kdc_address, peer_address
        self.master_key = ascii_key(master_key.decode("ascii"))
        self.log = log
        self.inbox = queue.Queue()
        self.connected = threading.Event()
        self._stop = threading.Event()
        self._key_lock = threading.Lock()
        self._session_lock = threading.Lock()
        self._handshake_lock = threading.Lock()
        self._used_tickets = {}
        self._session = None
        self._listener = None
        self._thread = None

    @property
    def session(self):
        with self._session_lock:
            return self._session

    def start(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((self.host, self.port))
            listener.listen(8)
            listener.settimeout(0.5)
        except BaseException:
            listener.close()
            raise
        
        self._listener = listener
        self.port = listener.getsockname()[1]
        self._thread = threading.Thread(target=self._accept, daemon=True)
        self._thread.start()
        self.log(f"[{self.name}] Mendengarkan {self.host}:{self.port}.")

    def _accept(self):
        while not self._stop.is_set():
            try:
                connection, address = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            
            threading.Thread(target=self._respond, args=(connection, address), daemon=True).start()

    def _dial(self, address):
        source = None if self.host == "0.0.0.0" else (self.host, 0)
        return socket.create_connection(address, timeout=8, source_address=source)

    def _ensure_available(self):
        if self._stop.is_set():
            raise ProtocolError("Peserta sudah dihentikan.")
        
        session = self.session
        
        if session is not None and session.expires_at <= time.time():
            self._dispose(session)
            session = None
        
        if session is not None:
            raise ProtocolError("Masih ada sesi aktif. Jalankan /close dahulu.")

    def _activate(self, connection, material, key):

        check_session(material, material["id_a"], material["id_b"])
        
        session = Session(
            connection, key, 
            material["session_id"], 
            material["id_a"],
            material["id_b"], 
            material["expires_at"],
        )

        with self._session_lock:
            if self._session is not None or self._stop.is_set():
                raise ProtocolError("Sesi lain aktif atau program sudah dihentikan.")
            
            connection.settimeout(None)
            self._session = session
            self.connected.set()
        
        threading.Thread(
            target=self._receive, 
            args=(session,), 
            daemon=True).start()

        self.log(f"[SESI] {self.name} siap chat dengan {self.peer_name}; ID={session.session_id}.")
        
        return session

    def connect(self):
        if not self._handshake_lock.acquire(blocking=False):
            raise ProtocolError("Pembentukan sesi lain sedang berlangsung.")
        
        connection = None
        activated = False

        try:
            self._ensure_available()
            id_a, id_b, n1 = self.name, self.peer_name, nonce()

            with self._key_lock:
                master_key = self.master_key

            with self._dial(self.kdc_address) as kdc:
                request = {"step": 1, "id_a": id_a, "id_b": id_b, "n1": n1}
                send_packet(kdc, request)
                self.log(f"[1] {id_a} -> KDC: ID_A={id_a}, ID_B={id_b}, N1={n1}")
                reply = recv_packet(kdc)

            expect_step(reply, 2)
            
            material = unprotect(
                master_key, reply.get("for_a"), 
                f"kdc-reply:{id_a}:{id_b}"
            )

            key = check_session(material, id_a, id_b)
            if material.get("n1") != n1:
                raise ProtocolError("N1 pada balasan KDC tidak cocok dengan permintaan.")
            
            ticket = reply.get("ticket")
            if not isinstance(ticket, dict):
                raise ProtocolError("Balasan KDC tidak membawa tiket.")
            
            self.log(f"[2] N1 cocok; paket_A Hex={ciphertext_log(reply['for_a'])}")
            self.log("[2] Key sesi didapat; tiket untuk peer diteruskan tanpa dibuka.")

            connection = self._dial(self.peer_address)

            send_packet(connection, {"step": 3, "ticket": ticket})
            self.log(f"[3] {id_a} -> {id_b}: tiket Hex={ciphertext_log(ticket)}")
            
            challenge = recv_packet(connection)
            expect_step(challenge, 4)

            payload = unprotect(
                key, 
                challenge.get("payload"), 
                f"challenge:{id_a}:{id_b}"
            )

            if payload.get("session_id") != material["session_id"]:
                raise ProtocolError("Tantangan bukan untuk sesi ini.")
            
            n2 = payload.get("n2")

            if not isinstance(n2, str) or not n2.isascii() or not n2.isdigit() or len(n2) > 39:
                raise ProtocolError("N2 bukan tantangan numerik yang valid.")
            
            n2_number = int(n2)

            if not 0 < n2_number < 2**128:
                raise ProtocolError("N2 di luar rentang 128 bit.")

            self.log(f"[4] Tantangan diterima; ciphertext Hex={ciphertext_log(challenge['payload'])}")
            
            answer = protect(
                key, {
                    "session_id": material["session_id"], 
                    "response": str(n2_number - 1),
                }, 
                f"response:{id_a}:{id_b}"
            )

            send_packet(connection, {"step": 5, "payload": answer})
            self.log(f"[5] f(N2)=N2-1 dikirim; ciphertext Hex={ciphertext_log(answer)}")
            
            session = self._activate(connection, material, key)
            activated = True
            
            return session

        finally:
            if connection is not None and not activated:
                connection.close()
            self._handshake_lock.release()

    def _respond(self, connection, address):
        acquired = self._handshake_lock.acquire(blocking=False)
        activated = False

        try:
            connection.settimeout(8)
            if not acquired:
                raise ProtocolError("Pembentukan sesi lain sedang berlangsung.")
            self._ensure_available()
            
            request = recv_packet(connection)
            expect_step(request, 3)
            ticket = request.get("ticket")
            id_a, id_b = self.peer_name, self.name
            
            with self._key_lock:
                master_key = self.master_key
            
            material = unprotect(master_key, ticket, f"ticket:{id_b}")
            
            key = check_session(material, id_a, id_b)
            
            now = time.time()
            self._used_tickets = {sid: expiry for sid, expiry in self._used_tickets.items() if expiry > now}
            
            if material["session_id"] in self._used_tickets:
                raise ProtocolError("Tiket sudah pernah dipakai (replay).")
            self._used_tickets[material["session_id"]] = material["expires_at"]
            
            self.log(f"[3] {id_a} ({address[0]}) -> {id_b}: tiket dibuka; Hex={ciphertext_log(ticket)}")
            
            n2 = secrets.randbelow(2**128 - 1) + 1
            
            challenge = protect(
                key, {
                    "session_id": material["session_id"],
                    "n2": str(n2),
                }, 
                f"challenge:{id_a}:{id_b}"
            )

            send_packet(
                connection, {
                    "step": 4, 
                    "payload": challenge
                }
            )

            self.log(f"[4] {id_b} -> {id_a}: tantangan Hex={ciphertext_log(challenge)}")
            
            answer = recv_packet(connection)
            expect_step(answer, 5)
            payload = unprotect(
                key, answer.get("payload"), 
                f"response:{id_a}:{id_b}"
            )

            if payload.get("session_id") != material["session_id"] or payload.get("response") != str(n2 - 1):
                raise ProtocolError("Jawaban f(N2) tidak sesuai.")
            
            check_session(material, id_a, id_b)
            
            self.log("[5] Jawaban f(N2) cocok; autentikasi penguasaan key berhasil.")
            self._activate(connection, material, key)
            
            activated = True

        except (OSError, EOFError, ValueError, TypeError, KeyError) as exc:
            self.log(f"[TOLAK] {self.name}: {exc}")
            
            try:
                send_packet(connection, {"type": "error", "message": "Pembentukan sesi ditolak."})
            except OSError:
                pass

        finally:
            if not activated:
                connection.close()
            
            if acquired:
                self._handshake_lock.release()

    def _require_session(self):
        session = self.session
        
        if session is None or session.closed.is_set():
            raise ProtocolError("Belum ada sesi. Jalankan /connect atau tunggu peer.")
        
        if session.expires_at <= time.time():
            self._dispose(session)
            raise ProtocolError("Sesi sudah kedaluwarsa. Jalankan /connect lagi.")
        
        return session

    def _send_record(self, session, kind, text=""):
        with session.send_lock:
            if session.closed.is_set() or session.expires_at <= time.time():
                raise ProtocolError("Sesi sudah ditutup atau kedaluwarsa.")
            
            sequence = session.send_sequence + 1
            
            payload = {
                "session_id": session.session_id, 
                "sender": self.name,
                "receiver": self.peer_name, 
                "seq": sequence, 
                "kind": kind,
            }

            if kind == "chat":
                payload["text"] = text

            envelope = protect(
                session.key, 
                payload, 
                f"chat:{self.name}:{self.peer_name}"
            )

            send_packet(
                session.connection, {
                    "type": "data", 
                    "payload": envelope
                }
            )

            session.send_sequence = sequence

            if kind == "chat":
                self.log(f"[AES KIRIM #{sequence}] ciphertext Hex={ciphertext_log(envelope)}")

    def send_text(self, text):
        ascii_plaintext(text)
        session = self._require_session()
        
        try:
            self._send_record(session, "chat", text)
        except (OSError, ValueError):
            self._dispose(session)
            raise
        
        self.log(f"[{self.name} -> {self.peer_name}] {text}")

    def _receive(self, session):
        try:
            while not session.closed.is_set():
                packet = recv_packet(session.connection)

                if packet.get("type") != "data":
                    raise ProtocolError("Paket aplikasi tidak valid.")
                
                value = unprotect(
                    session.key, 
                    packet.get("payload"), 
                    f"chat:{self.peer_name}:{self.name}"
                )
                
                if session.expires_at <= time.time():
                    raise ProtocolError("Sesi sudah kedaluwarsa.")
                
                if value.get("session_id") != session.session_id:
                    raise ProtocolError("Pesan berasal dari sesi lain.")
                
                if value.get("sender") != self.peer_name or value.get("receiver") != self.name:
                    raise ProtocolError("Identitas pengirim/penerima pesan tidak sesuai.")
                
                sequence = value.get("seq")
                
                if type(sequence) is not int or sequence != session.receive_sequence + 1:
                    raise ProtocolError("Nomor urut pesan salah atau pesan diputar ulang.")
                
                session.receive_sequence = sequence
                
                if value.get("kind") == "close":
                    self.log(f"[SESI] {self.peer_name} menutup sesi.")
                    break
                
                if value.get("kind") != "chat":
                    raise ProtocolError("Jenis pesan tidak dikenal.")
                
                text = ascii_plaintext(value.get("text"))
                
                self.inbox.put((self.peer_name, text))
                self.log(f"[AES TERIMA #{sequence}] ciphertext Hex={ciphertext_log(packet['payload'])}")
                self.log(f"[{self.peer_name} -> {self.name}] {text}")

        except EOFError:
            if not session.closed.is_set():
                self.log(f"[SESI] Koneksi {self.peer_name} berakhir.")
        
        except (OSError, ValueError, TypeError, KeyError) as exc:
            if not session.closed.is_set():
                self.log(f"[TOLAK] Pesan/koneksi {self.name}: {exc}")
        
        finally:
            self._dispose(session)

    def _dispose(self, session):
        session.closed.set()
        
        try:
            session.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        
        session.connection.close()
        
        with self._session_lock:
            if self._session is session:
                self._session = None
                self.connected.clear()

    def close_session(self):
        session = self.session
        
        if session:
            try:
                self._send_record(session, "close")
            except (OSError, ValueError):
                pass
            
            self._dispose(session)

    def set_master_key(self, key):
        key = ascii_key(key.decode("ascii"))
        
        if not self._handshake_lock.acquire(blocking=False):
            raise ProtocolError("Tunggu pembentukan sesi selesai sebelum mengganti key.")
        
        try:
            self._ensure_available()
            with self._key_lock:
                self.master_key = key
        
        finally:
            self._handshake_lock.release()
        
        self.log(f"[{self.name}] Key jangka panjang diperbarui. Samakan dengan key di KDC.")

    def status(self):
        session = self.session
        if session is None:
            return f"{self.name}: belum ada sesi; peer={self.peer_name} {self.peer_address}."
        
        remaining = max(0, int(session.expires_at - time.time()))
        
        role = "initiator (A)" if session.id_a == self.name else "responder (B)"
        
        return f"{self.name}: {role}, sesi={session.session_id}, sisa={remaining}s."

    def stop(self):
        self._stop.set()
        self.close_session()

        if self._listener:
            self._listener.close()

        if self._thread:
            self._thread.join(timeout=2)


HELP = '''Perintah:
  /connect  : mulai lima langkah KDC (Alice maupun Bob boleh memulai)
  /status   : tampilkan status sesi tanpa mencetak key
  /key      : ubah key sendiri; /close dahulu, lalu samakan key di KDC
  /close    : tutup sesi; /connect berikutnya memperoleh key sesi baru
  /help     : tampilkan bantuan
  /quit     : keluar
Ketik pesan ASCII biasa untuk mengirim chat setelah sesi terbentuk.
'''


def main(name):
    peer_name = opposite(name)
    parser = argparse.ArgumentParser(description=f"Peserta {name}; AES-128 manual dan KDC.")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9001 if name == "alice" else 9002)
    parser.add_argument("--kdc-ip", required=True)
    parser.add_argument("--kdc-port", type=int, default=9000)
    parser.add_argument("--peer-ip", required=True, help=f"IP perangkat {peer_name}.")
    parser.add_argument("--peer-port", type=int, default=9002 if name == "alice" else 9001)
    parser.add_argument("--key-file", help="Berkas privat berisi key milik peserta ini saja.")
    parser.add_argument("--no-console", action="store_true")
    args = parser.parse_args()
    participant = None
    
    try:
        key = read_key_file(args.key_file) if args.key_file else prompt_key(f"Key {name}–KDC")
        participant = Participant(
            name, 
            args.host, 
            args.port,
            (args.kdc_ip, args.kdc_port), 
            (args.peer_ip, args.peer_port), 
            key
        )

        participant.start()
        
        if args.no_console:
            while True:
                participant._stop.wait(1)

        print(HELP)

        while True:
            line = input(f"{name}> ")
            try:
                if line == "/quit":
                    break
                
                if line == "/connect":
                    participant.connect()
                
                elif line == "/status":
                    print(participant.status())
                
                elif line == "/key":
                    if participant.session is not None:
                        raise ProtocolError("Jalankan /close sebelum mengganti key.")
                    
                    participant.set_master_key(prompt_key(f"Key baru {name}–KDC"))
                
                elif line == "/close":
                    participant.close_session()
                
                elif line == "/help":
                    print(HELP)
                
                elif line.startswith("/"):
                    print("Perintah tidak dikenal. Gunakan /help.")
                
                elif line:
                    participant.send_text(line)

            except (OSError, EOFError, ValueError, TypeError, KeyError) as exc:
                print(f"Operasi gagal: {exc}")
    
    except (KeyboardInterrupt, EOFError):
        pass
    
    except (OSError, ValueError, TypeError) as exc:
        parser.exit(1, f"Gagal menjalankan {name}: {exc}\n")
    
    finally:
        if participant:
            participant.stop()
