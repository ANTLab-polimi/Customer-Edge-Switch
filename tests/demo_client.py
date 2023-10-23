#!/usr/bin/python3

"""
    Script which simulates a NILM (Non Intrusive Load Monitoring) sensor of a industrial environment
    capturing the data about the power consumed by the selected appliances
"""

import socket
import time
import pandas as pd

HOST = "192.168.2.2"  # The server's hostname or IP address
PORT = 80  # The port used by the server
# The file with the NILM sensors' data to be sent
file_to_send = "../nilmtk_application/hipe/hipe_cleaned_v1.0.1_geq_2017-10-01_lt_2018-01-01/MainTerminal_PhaseCount_3_geq_2017-10-01_lt_2018-01-01.csv"


def start_demo():

    # we supppose that the client could be composed by a common TCP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

        s.connect((HOST, PORT))

        print("Reading the csv file...")
        df = pd.read_csv(file_to_send)

        # reading the wanted columns for the test: the timestamp and the total power
        # captured in that moment 
        my_df = df.loc[:,["SensorDateTime", "P_kW"]]
        
        # sending one by one row at time to the server
        for i in range(0, len(my_df)):
            
            # locating the ith row
            row_data = my_df.loc[i]

            # converting it into csv format and then into bytes
            bytes_data = row_data.to_csv().encode()
            print(bytes_data)

            # waiting 5 seconds to send a row emulating a real sensor 
            time.sleep(5)

            # sending all the bytes data read in this way
            s.sendall(bytes_data)
    
    s.close()

    return


if __name__ == "__main__":
    start_demo()
