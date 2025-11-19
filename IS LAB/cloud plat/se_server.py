# server_simple.py
# Minimal server: stores only encrypted records + metadata.
# One request per connection. Supports {op:"ADD"} and {op:"SEARCH"}.
import socket, json

HOST, PORT = "127.0.0.1", 50555
DB = []  # each: {"cipher": str, "hash": str, "sig": int, "pub": {"n":int,"e":int}}

def handle(req):
    op = req.get("op")
    if op == "ADD":
        DB.append({"cipher": req["cipher"], "hash": req["hash"],
                   "sig": req["sig"], "pub": req["pub"]})
        return {"ok": True, "stored": len(DB)}
    if op == "SEARCH":
        enc_kw = req["enc_kw"]
        matches = [r for r in DB if enc_kw in r["cipher"]]
        return {"ok": True, "matches": matches}
    return {"ok": False, "error": "unknown op"}

def main():
    print(f"[server] listening on {HOST}:{PORT}")
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT)); s.listen(5)
        while True:
            conn, _ = s.accept()
            with conn:
                data = conn.recv(65535)
                if not data: continue
                req = json.loads(data.decode())
                resp = handle(req)
                conn.sendall(json.dumps(resp).encode())

if __name__ == "__main__":
    main()