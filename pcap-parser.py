import argparse
import sys
import os
from xlsxwriter import Workbook
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP


def __build_header(src_urls, dst_urls):
    return f"{str(src_urls)} -> {str(dst_urls)}"


def process_pcap(opts):
    with Workbook(opts.dst_file) as workbook:
        worksheet = workbook.add_worksheet()

        row_header = __build_header(opts.srcurls, opts.dsturls)
        worksheet.write(0, 0, row_header)

        packets = RawPcapReader(opts.pcap_file)
        nline = 1
        pkts_length = 0
        for (pkt_data, pkt_metadata,) in packets:
            ether_pkt = Ether(pkt_data)
            packet_fields = ether_pkt.fields

            if 'type' not in ether_pkt.fields:
                continue

            if len(opts.srcurls) != 0 and packet_fields['src'] not in opts.srcurls:
                continue

            if len(opts.dsturls) != 0 and packet_fields['dst'] not in opts.dsturls:
                continue

            nline += 1
            pkts_length = pkt_metadata.caplen
            worksheet.write(nline, 0, pkts_length)
            worksheet.write(nline, 1, packet_fields['src'])
            worksheet.write(nline, 2, packet_fields['dst'])




def __create_argparser():
    parser = argparse.ArgumentParser(prog='tcpdump-parser', add_help=True)

    parser.add_argument('--pcap-file', required=True)
    parser.add_argument('--dst-file', default='pcap_xlsx.xlsx')
    parser.add_argument('--srcurls', type=str, default=[], nargs='+')
    parser.add_argument('--dsturls', type=str, default=[], nargs='+')
    parser.add_argument('-i', '--interval', default=2, type=int, help='Capture info about packets from spec interval')

    return parser


def main(*args):
    parser = __create_argparser()
    opts = parser.parse_args(*args)

    if not os.path.isfile(opts.pcap_file):
        print('"{}" does not exist'.format(opts.pcapf_ile), file=sys.stderr)
        sys.exit(-1)

    process_pcap(opts)
    sys.exit(0)


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except Exception as ex:
        sys.stderr.write(f'{str(ex)}\n')
        sys.exit(1)
