# import for the conversion of selected data from the csv format into
# the NILMTK HDF5 format (if *, all converters are included)
from nilmtk.dataset_converters import *

# to open the data converted and to print the info about that dataset

from nilmtk import DataSet
from nilmtk.utils import *

#greend password is vienna
# example with another dataset
# convert_redd('/data/REDD/low_freq', '/data/redd.h5')
print("converting...")
convert_greend('./greend_data_building', './greend_data_converter/greend.h5')
print("conversion finished")
greend = DataSet('./greend_data_converter/greend.h5')

print_dict(greend.metadata)

print_dict(greend.buildings)

print_dict(greend.buildings[1].metadata)

elec = greend.buildings[1].elec

# now there is the part for loading data into memory
