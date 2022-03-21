import socket

def netcat(hostname, port, content):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("45.45.0.2", 1298))
    print("CONNECTION: " + str(time.time()))
    s.connect((hostname, port))
    s.sendall(content)
    s.shutdown(socket.SHUT_WR)
    print("Connection closed.")
    s.close()