import argparse
import sys
import os
import datetime
import socket

from xlsxwriter import Workbook
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from dataclasses import dataclass


@dataclass
class PacketsBundle:
    src_hosts: list
    dst_hosts: list
    src_pkts_len: int = 0
    dst_pkts_len: int = 0

    def inc_period_line_value(self, ip_pkt, datalen):
        if ip_pkt.underlayer.src in self.src_hosts and ip_pkt.underlayer.dst in self.dst_hosts:
            self.src_pkts_len += datalen
        elif ip_pkt.underlayer.src in self.dst_hosts and ip_pkt.underlayer.dst in self.src_hosts:
            self.dst_pkts_len += datalen

        # if len(self.src_hosts) != 0 and ip_pkt.underlayer.src in self.src_hosts:
        #     self.src_pkts_len += datalen
        #
        # if len(self.dst_hosts) != 0 and ip_pkt.underlayer.dst in self.dst_hosts:
        #     self.dst_pkts_len += datalen

    def reset_lens(self):
        self.src_pkts_len = 0
        self.dst_pkts_len = 0


def __build_header(pkt_bundle):
    return f"{str(pkt_bundle.src_hosts)} -> {str(pkt_bundle.dst_hosts)}"


def __is_packet_with_correct_urls(ip_pkt, opts):
    if len(opts.src_hosts) != 0 and ip_pkt.src in opts.src_hosts:
        return False

    if len(opts.dst_hosts) != 0 and ip_pkt.dst in opts.dst_hosts:
        return False

    if len(opts.src_ports) != 0 and ip_pkt.payload.sport in opts.src_hosts:
        return False

    if len(opts.dst_ports) != 0 and ip_pkt.payload.dport in opts.dst_hosts:
        return False

    if len(opts.not_src_ports) != 0 and ip_pkt.payload.sport in opts.not_src_ports:
        return False

    if len(opts.not_dst_ports) != 0 and ip_pkt.payload.dport in opts.not_dst_ports:
        return False

    return True


def get_tcp_pkt(pkt_data):
    ether_pkt = Ether(pkt_data)

    if 'type' not in ether_pkt.fields:
        return None

    if ether_pkt.type != 0x0800:
        return None
    ip_pkt = ether_pkt[IP]

    if ip_pkt.proto != 6:
        return None
    tcp_pkt = ip_pkt[TCP]

    return tcp_pkt


def process_pcap(opts):
    packets = RawPcapReader(opts.pcap_file)
    with Workbook(opts.dst_file) as workbook:
        worksheet = workbook.add_worksheet()
        pkts_bundle = PacketsBundle(src_hosts=opts.src_hosts, dst_hosts=opts.dst_hosts)
        row_header = __build_header(pkts_bundle)
        worksheet.write(0, 0, row_header)

        nline = 1
        interval = datetime.timedelta(seconds=opts.interval)
        last_period = datetime.datetime.fromtimestamp(0)
        for (pkt_data, pkt_metadata,) in packets:
            tcp_pkt = get_tcp_pkt(pkt_data)
            if not tcp_pkt:
                continue

            packet_datetime = datetime.datetime.fromtimestamp(pkt_metadata.sec)
            while packet_datetime > last_period:
                worksheet.write(nline, 0, pkts_bundle.src_pkts_len)
                worksheet.write(nline, 1, pkts_bundle.dst_pkts_len)
                last_period = datetime.datetime.fromtimestamp(pkt_metadata.sec) + interval
                pkts_bundle.reset_lens()
                nline += 1

            pkts_bundle.inc_period_line_value(tcp_pkt, pkt_metadata.caplen)


def __create_argparser():
    default_host = [socket.gethostbyname(socket.gethostname())]
    parser = argparse.ArgumentParser(prog='tcpdump-parser', add_help=True)

    parser.add_argument('--pcap-file', required=True)
    parser.add_argument('--dst-file', default='pcap_xlsx.xlsx')

    parser.add_argument('--src-hosts', type=str, default=default_host, nargs='+')
    parser.add_argument('--dst-hosts', type=str, default=default_host, nargs='+')
    parser.add_argument('--src-ports', type=int, default=[], nargs='+')
    parser.add_argument('--dst-ports', type=int, default=[], nargs='+')
    parser.add_argument('--not-src-ports', type=int, default=[], nargs='+')
    parser.add_argument('--not-dst-ports', type=int, default=[], nargs='+')

    parser.add_argument('-i', '--interval', default=2, type=float, help='Capture info about packets from spec interval')

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
