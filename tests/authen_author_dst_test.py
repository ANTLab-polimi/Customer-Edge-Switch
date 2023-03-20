import socket
import time

controller_ip = "192.168.56.2"
host = "0.0.0.0"
self_ip = "192.168.56.6"
iface = "eth1"
http_port = 80

# it's a simple echo socket TCP on the service port
def dst_test():
    
    print("OPEN AN ECHO SOCKET TCP ON PORT " + str(http_port))
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # it's not relevant if the socket is binded to the iface eth1, it can receive the packets

    #bind_to_device = IN.SO_BINDTODEVICE
    # 25 only if ON LINUX
    #bind_to_device = 25
    #s.setsockopt(socket.SOL_SOCKET, bind_to_device, str("eth1" + '\0').encode('utf-8'))

    s.bind((host, http_port))
    s.listen()
    while True:
        print(f"Waiting for a connection...")
        conn, addr = s.accept()
        with conn:
            try:
                print(f"Connected by {addr}")
                # loop to echo the data
                i = 0
                while True:
                    time.sleep(2)
                    data = conn.recv(1024)
                    if not data and i < 5:
                        print("NO DATA :(")
                        i = i + 1
                    elif not data and i >= 5:
                        # listen another connection
                        i = 0
                        break
                    else:
                        print("DATA RECEIVED: " + str(data))
                        msg = b"HELLO FROM THE SERVER :D"
                        conn.send(msg)
            finally:
                conn.close()


if __name__ == "__main__":
    dst_test()