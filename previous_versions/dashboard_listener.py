import socket
import os

SOCK_PATH = "/tmp/ndr.sock"

# Usuwamy stare gniazdo, jeśli istnieje
if os.path.exists(SOCK_PATH):
    os.remove(SOCK_PATH)

server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(SOCK_PATH)
# Ustawiamy uprawnienia, żeby sensor (sudo) i dashboard mogły pisać do pliku
os.chmod(SOCK_PATH, 0o777) 
server.listen(1)

print(f"[*] Python Listener: Oczekiwanie na alerty z sensora na {SOCK_PATH}...")

try:
    while True:
        conn, addr = server.accept()
        data = conn.recv(1024)
        if data:
            print(f"[ALERT ODEBRANY]: {data.decode('utf-8')}")
        conn.close()
except KeyboardInterrupt:
    print("\n[*] Zamykanie listenera...")
finally:
    os.remove(SOCK_PATH)