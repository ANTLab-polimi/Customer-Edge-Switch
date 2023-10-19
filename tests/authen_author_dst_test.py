import socket
import time
from os.path import exists
import pandas as pd
import os
import nilm_ml

# global variables section
controller_ip = "192.168.2.1"
host = "0.0.0.0"
self_ip = "192.168.2.2"
iface = "eno1"
http_port = 80
output_filename = "./mains_csv/MainTerminal_PhaseCount.csv"

# it's a simple server socket TCP on the service port HTTP
def dst_test():
    # check if the file path exists
    file_exists = exists(output_filename)
    if not file_exists:
        # if not, create that file, in this way I can guarantee the the existence
        # of that file avoiding any problem
        os.mknod(output_filename)

    # these are the possible states of the system
    set_of_possible_system_states = nilm_ml.calculate_possible_system_states()

    print("OPEN AN ECHO SOCKET TCP ON PORT " + str(http_port))
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    '''
        it's not relevant if the socket is binded to "iface", it can receive the packets

        bind_to_device = IN.SO_BINDTODEVICE
        bind_to_device = 25 (only if ON LINUX)

        s.setsockopt(socket.SOL_SOCKET, bind_to_device, str(iface + '\0').encode('utf-8'))
    '''
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
                    # a little delay to give time to the client
                    time.sleep(0.2)
                    print(f"Waiting for data...")

                    '''
                        I am supposing that the server will receive
                        only one row at a time and that row is not longer than 1024 bytes
                    '''

                    data = conn.recv(1024).decode('utf-8')

                    '''
                        A bit of parsing to recreate a list of one element
                        which is going to be inserted in the csv file
                    '''

                    # creating a list and split it in three element, removing the '\n'
                    row = data.strip().split('\n')

                    # removing the index (the first element)
                    row.pop(0)

                    # splitting the "SensorDateTime,2017-10-01T00:10:13.623+02" in position 0
                    csv_time = row[0].split(',')
                    csv_time = csv_time[1]
                    # retrieving only the hours:minutes:seconds:milliseconds
                    csv_time = csv_time[11:-3]
                    # splitting the "P_kW,6.569999933242798" in position 1
                    csv_power = row[1].split(',')
                    csv_power = csv_power[1]
                    
                    # selecting the optimal state of the system
                    current_system_state = nilm_ml.get_state(set_of_possible_system_states, csv_power)

                    # creating a list with the timestamp and the total power consumption
                    my_list = []
                    my_list.append(csv_time)
                    my_list.append(csv_power)

                    # popping the total power nearest to the current one
                    current_system_state.pop(0)

                    # appending the power of each electrical device in the system
                    for j in current_system_state:
                        my_list.append(str(j[1]))

                    # appending it in a list in order to have a list of list which is representing
                    # an element on the external list
                    final_list = []
                    final_list.append(my_list)
                    
                    # creating the data frame with pandas
                    # giving the name for the columns
                    columns = ['Sensor Date Time', 'kW', 'Chip Press', 'Chip Saw', 'High Temperature Oven', 'Soldering Oven', 'Washing Machine']
                    df = pd.DataFrame(final_list, columns=columns)
                    print(df)
                    # reading the csv
                    current_df = pd.read_csv(output_filename)

                    # concatenating the already present df taken from the current csv
                    # with the new data frame 
                    # and writing the dataframe into the new csv file
                    # (which has the same name)
                    final_df = pd.concat([current_df, df], ignore_index=True)
                    final_df.to_csv(output_filename, index=False)

            except Exception as e:
                print(e)

    conn.close()


if __name__ == "__main__":
    dst_test()
