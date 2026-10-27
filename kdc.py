import argparse
import socket
import threading
import time

from aes import ascii_key
from protocol import (
    IDENTITIES, 
    check_nonce, 
    ciphertext_log, 
    expect_step, 
    load_kdc_keys, 
    new_session_key, 
    nonce, 
    prompt_key,
)
from wire import ProtocolError, protect, recv_packet, send_packet

class KeyDistributionCenter:
    def __init__(self, host, port, keys, ttl=300, log=print):
        if set(keys) != IDENTITIES or any(not isinstance(k, bytes) or len(k) != 16 for k in keys.values()):
            raise ValueError("KDC memerlukan key 16 byte untuk alice dan bob.")

        if not 1 <= ttl <= 3600:
            raise ValueError("TTL harus 1 sampai 3600 detik.")

        self.host, self.port, self.ttl = host, port, ttl
        self.keys = {name: ascii_key(key.decode("ascii")) for name, key in keys.items()}
        self.log = log
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._listener = None
        self._thread = None

    def start(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((self.host, self.port))
            listener.listen(16)
            listener.settimeout(0.5)
        except BaseException:
            listener.close()
            raise

        self._listener = listener
        self.port = listener.getsockname()[1]
        self._thread = threading.Thread(target=self._accept, daemon=True)
        self._thread.start()
        self.log(f"[KDC] Mendengarkan {self.host}:{self.port}; TTL tiket {self.ttl}s.")

    def _accept(self):
        while not self._stop.is_set():
            try:
                connection, address = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            
            threading.Thread(target=self._handle, args=(connection, address), daemon=True).start()

    def _handle(self, connection, address):
        with connection:
            connection.settimeout(8)
            try:
                request = recv_packet(connection)
                expect_step(request, 1)

                id_a, id_b = request.get("id_a"), request.get("id_b")
                if not isinstance(id_a, str) or not isinstance(id_b, str):
                    raise ProtocolError("Identitas harus string.")
                if id_a not in IDENTITIES or id_b not in IDENTITIES or id_a == id_b:
                    raise ProtocolError("Pasangan identitas tidak terdaftar.")

                n1 = check_nonce(request.get("n1"))
                self.log(f"[1] {id_a} ({address[0]}) -> KDC: ID_A={id_a}, ID_B={id_b}, N1={n1}")
                
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

                #enkripsi paket untuk alice
                for_a = protect(
                    key_a, 
                    {**common, "n1": n1}, 
                    f"kdc-reply:{id_a}:{id_b}"
                )

                #buat ticket untuk bob
                ticket = protect(key_b, common, f"ticket:{id_b}")
                send_packet(connection, {"step": 2, "for_a": for_a, "ticket": ticket})
                self.log(f"[2] KDC -> {id_a}: paket_A Hex={ciphertext_log(for_a)}")
                self.log(f"[2] KDC -> {id_a}: tiket_B Hex={ciphertext_log(ticket)}")
                
            except (OSError, EOFError, ValueError, TypeError, KeyError) as exc:
                self.log(f"[KDC] Permintaan ditolak: {exc}")
                
                try:
                    send_packet(connection, {"type": "error", "message": "Permintaan KDC tidak valid."})
                except OSError:
                    pass

    def set_key(self, name, key):
        if name not in IDENTITIES:
            raise ValueError("Identitas tidak terdaftar.")
        
        key = ascii_key(key.decode("ascii"))
        
        with self._lock:
            self.keys[name] = key
        
        self.log(f"[KDC] Key {name} diperbarui untuk penerbitan sesi berikutnya.")

    def stop(self):
        self._stop.set()
        
        if self._listener:
            self._listener.close()
        
        if self._thread:
            self._thread.join(timeout=2)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--ttl", type=int, default=300, help="Masa berlaku sesi, dalam detik (1..3600).")
    parser.add_argument("--keys-file", help='JSON privat KDC: {"alice": "...", "bob": "..."}')
    parser.add_argument("--no-console", action="store_true")
    args = parser.parse_args()
    server = None
    try:
        keys = load_kdc_keys(args.keys_file) if args.keys_file else {
            name: prompt_key(f"Key {name}–KDC") for name in sorted(IDENTITIES)
        }
        
        server = KeyDistributionCenter(args.host, args.port, keys, args.ttl)
        
        server.start()
        
        if args.no_console:
            while True:
                server._stop.wait(1)
        
        print("Perintah: /key alice, /key bob, /help, /quit")
        
        while True:
            command = input("kdc> ").strip()
            
            if command == "/quit":
                break
            
            if command in {"/key alice", "/key bob"}:
                name = command.split()[1]
                server.set_key(name, prompt_key(f"Key baru {name}–KDC"))
            
            elif command:
                print("Perintah: /key alice, /key bob, /help, /quit")
    
    except (KeyboardInterrupt, EOFError):
        pass
    
    except (OSError, ValueError, TypeError) as exc:
        parser.exit(1, f"Gagal menjalankan KDC: {exc}\n")
    
    finally:
        if server:
            server.stop()

if __name__ == "__main__":
    main()
