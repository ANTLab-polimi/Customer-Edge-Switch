import socket

controller_ip = "192.168.56.2"
host = "127.0.0.1"
self_ip = "192.168.56.6"
iface = "eth1"
http_port = 80

def dst_test():
    # open an echo socket TCP on port 80
    print("OPEN AN ECHO SOCKET TCP ON PORT " + str(http_port))
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, http_port))
    s.listen()
    conn, addr = s.accept()
    with conn:
        printf(f"Connected by {addr}")
        # loop to echo the data
        while True:
            data = conn.recv(1024)
            if not data:
                break
            print(str(data))
            conn.senddall(data)


if __name__ == "__main__":
    dst_test()