#python2

from p4_mininet import P4Switch, P4Host

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.link import TCLink
from mininet.cli import CLI

from p4runtime_switch import P4RuntimeSwitch
import p4runtime_lib.simple_controller

import os, argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--switch-id', type=int, required=False, default=0)
    parser.add_argument('-f', '--p4runtime-file', type=str, required=True)
    parser.add_argument('-g', '--grpc-port', type=int, required=False, default=50051)

    args = parser.parse_args()

    cwd = os.getcwd()
    default_logs = os.path.join(cwd, 'logs')

    print('configuring switch {} using P4Runtime with file {}'.format(args.switch_id, args.p4runtime_file))
    with open(args.p4runtime_file, 'r') as sw_conf_file:
        outfile = '%s/%s-p4runtime-requests.txt' %(default_logs, args.switch_id)
        p4runtime_lib.simple_controller.program_switch(
            addr='127.0.0.1:{}'.format(args.grpc_port),
            device_id=args.switch_id,
            sw_conf_file=sw_conf_file,
            workdir=os.getcwd(),
            proto_dump_fpath=outfile)