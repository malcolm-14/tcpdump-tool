import argparse
import sys
import os
import xlsxwriter
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP


def parse_data(opts):
    pass


def process_pcap(pcapfile, opts):
    workbook = xlsxwriter.Workbook()

    with xlsxwriter.Workbook() as workbook:
        worksheet = workbook.add_worksheet()
        packets = RawPcapReader(pcapfile)
        for (pkt_data, pkt_metadata,) in packets:

            ether_pkt = Ether(pkt_data)
            packet_fields = ether_pkt.fields

            if 'type' not in ether_pkt.fields:
                continue
                
            if packet_fields['dst'] not in opts.resurls:
                continue

            if packet_fields['scc'] not in opts.dsturls:
                continue

            worksheet.write(nline, 0, )




def __create_argparser():
    parser = argparse.ArgumentParser(prog='tcpdump-parser', add_help=True)

    parser.add_argument('--pcapfile', required=True)
    parser.add_argument('--srcurls', type=str, default=[], nargs='+')
    parser.add_argument('--dsturls', type=str, default=[], nargs='+')
    parser.add_argument('-i', '--interval', default=2, type=int, help='Capture info about packets from spec interval')

    return parser


def main(*args):
    parser = __create_argparser()
    opts = parser.parse_args(*args)

    file_name = opts.pcapfile
    if not os.path.isfile(file_name):
        print('"{}" does not exist'.format(file_name), file=sys.stderr)
        sys.exit(-1)

    process_pcap(file_name)
    sys.exit(0)


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except Exception as ex:
        sys.stderr.write(f'{str(ex)}\n')
        sys.exit(1)
