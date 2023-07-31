import socket
import time
from os.path import exists
from csv import writer

controller_ip = "192.168.2.1"
host = "0.0.0.0"
self_ip = "192.168.2.2"
iface = "eno1"
http_port = 80
output_filename = "./mains_csv/MainTerminal_PhaseCount.csv"

# it's a simple echo socket TCP on the service port
def dst_test():
    # check if te file path exists
    file_exists = exists(output_filename)
    if !file_exists:
        # if not, create that file, in this way I can guarantee the the existence
        # of that file avoiding any problem
        with open(output_filename, 'w') as f:
            f.close()

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
                # loop to take the data and store them in a .csv
                while True:
                    time.sleep(0.2)
                    print(f"Waiting for data...")

                    data = b""
                    while True:
                        chunk = conn.recv(1024).decode('utf-8')
                        if not chunk:
                            break
                        data += chunk
                    
                    # TODO DA VERIFICARE SE FUNZIONA
                    rows = data.strip().split('\n')

                    # I am supposing that the server will receive
                    # only one row at a time
                    # but I want to be sure to receive everything
                    for row in rows:
                        csv_row = row.split(',')
                        # appending the read row inside the csv file
                        with open(output_filename, 'a', newline='') as csv_file:
                            writer = csv.writer(csv_file)
                            writer.writerow(csv_row)

                    # printing for debug
                    print("Dati ricevuti:")
                    print(data.decode('utf-8'))

            except Exception as e:
                print(e)

    conn.close()


if __name__ == "__main__":
    dst_test()
