import pandas as pd

# output filename
output_filename = './final_csv.csv'
columns = ["SensorDataTime", "P_kW"]

# the top 5 appliance csv file
csv_filename1 = './hipe/hipe_cleaned_v1.0.1_geq_2017-10-01_lt_2018-01-01/ChipPress_PhaseCount_3_geq_2017-10-01_lt_2018-01-01.csv'
csv_filename2 = './hipe/hipe_cleaned_v1.0.1_geq_2017-10-01_lt_2018-01-01/ChipSaw_PhaseCount_3_geq_2017-10-01_lt_2018-01-01.csv'
csv_filename3 = './hipe/hipe_cleaned_v1.0.1_geq_2017-10-01_lt_2018-01-01/HighTemperatureOven_PhaseCount_3_geq_2017-10-01_lt_2018-01-01.csv'
csv_filename4 = './hipe/hipe_cleaned_v1.0.1_geq_2017-10-01_lt_2018-01-01/SolderingOven_PhaseCount_3_geq_2017-10-01_lt_2018-01-01.csv'
csv_filename5 = './hipe/hipe_cleaned_v1.0.1_geq_2017-10-01_lt_2018-01-01/WashingMachine_PhaseCount_3_geq_2017-10-01_lt_2018-01-01.csv'

print("reading the first csv file...")
# reading the csv
current_df = pd.read_csv(csv_filename2)

print("reading the csv file...")
# reading the csv files from where retrieving the data
df_1 = pd.read_csv(csv_filename1)
#df_2 = pd.read_csv(csv_filename2)
#df_3 = pd.read_csv(csv_filename3)
#df_4 = pd.read_csv(csv_filename4)
#df_5 = pd.read_csv(csv_filename5)

print("reducing to only two columns...")

df_1 = df_1.loc[:,["SensorDateTime", "P_kW"]]
#df_2 = df_2.loc[:,["SensorDateTime", "P_kW"]]
#df_3 = df_3.loc[:,["SensorDateTime", "P_kW"]]
#df_4 = df_4.loc[:,["SensorDateTime", "P_kW"]]
#df_5 = df_5.loc[:,["SensorDateTime", "P_kW"]]

# sending one by one row at time tp the server
for i in range(0, 10):#len(df_1)):
    # locating the ith row
    row_data_1 = df_1.loc[i]
    current_df_row_data = current_df.loc[i]

    print(row_data_1)
    print(current_df_row_data)

    current_df.loc[i][1] = round(current_df_row_data[1],2) + round(row_data_1[1],2)
    print(current_df.loc[i][1])

    print()
    print()