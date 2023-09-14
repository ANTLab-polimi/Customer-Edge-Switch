import copy

# the states that every electrical component can assume with the power assorbed in that state
states_ChipPress = [["off", 0.0],["on1",0.21],["on2",1.40],["on3",5.1],["on4",25.1]]
states_ChipSaw = [["off", 0.0],["on1",0.2],["on2",0.315]]
states_HighTemperatureOven = [["off", 0.0],["on1",0.1],["on2",2.2],["on3",4.0]]
states_SolderingOven = [["off", 0.0],["on1",0.2],["on2",3.9],["on3",7.5]]
states_WashingMachine = [["off", 0.0],["on1",0.5],["on2",1.0],["on3",10.0]]

electrical_devices = [states_ChipPress, states_ChipSaw, states_HighTemperatureOven, states_SolderingOven, states_WashingMachine]

# to retreive the power of the state of a device
# (key function for the sort)
def get_power(el):
    return el[0]

# it has to be lauched before to start the socket in order to have
# the total amount of possible states
def calculate_possible_system_states():

    # [[0.0,["off", 0.0],["off", 0.0],["off", 0.0],["off", 0.0],["off", 0.0]], ... ,[P_kW_max,["on4",25.1],["on2",0.315],["on3",4.0],["on3",7.5],["on3",10.0]]
    set_of_states_appliance = []

    # 5*3*4*4*4 = 960 possible states of the system, it should be ok and it is practically istantaneous
    for i in states_ChipPress:
        for j in states_ChipSaw:
            for k in states_HighTemperatureOven:
                for h in states_SolderingOven:
                    for l in states_WashingMachine:
                        system_state = [round((i[1])+(j[1])+(k[1])+(h[1])+(l[1]),2), i, j, k, h, l]
                        set_of_states_appliance.append(system_state)

    set_of_states_appliance.sort(key=get_power)
    
    return set_of_states_appliance

# it searches the power which has a minimum gap between itself and the current power of the system
def appending(set_states, nearest_states, current_power, margin):

    for i in set_states:
        # absolute value to avoid not considering also the values which are over the current power with a minimum slack margin
        if abs(float(current_power) - i[0]) < margin:
            nearest_states.append(copy.deepcopy(i))

# to get the current state of the system
def get_state(set_states, current_power):

    nearest_states = []
    margin = 0.0

    # at every iteration, the slack margin is released in order to find a possible state of the system
    while not nearest_states:
        appending(set_states, nearest_states, current_power, margin)
        margin = margin + 0.1
    
    nearest_states.sort(key=get_power)

    return nearest_states.pop(0)