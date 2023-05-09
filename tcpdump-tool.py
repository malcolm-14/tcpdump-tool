import argparse
import sys
import xlsxwriter
import regexp
import time
from collections import namedtuple


def __regexp_build(orient):
    pass


def write_to_workbook(workbook, datalen):
    pass


def parse_data(opts):
    workbook = xlsxwriter.Workbook(opts.destfile)
    # regexp_line = __regexp_build(opts.orientation)

    datalen = 0
    old_packet_time: time = 0
    with open(opts.srcfile) as datafile:
        for line in datafile.readline():
            line_arr = line.split(' ')

            # if regexp_line ....
            #   continue

            new_packet_time = time.strptime(line_arr[0], '%H:%M:%S.%f')
            if new_packet_time - old_packet_time < opts.interval:
                write_to_workbook(workbook, datalen)
                datalen = 0
                old_packet_time = new_packet_time


def cmd_handle(opts):
    if opts.command == 'parse':
        parse_data(opts)
    elif opts.command == 'dump':
        pass
    else:
        raise Exception(f'not found command "{opts.command}"')

def __create_argparser():
    parser = argparse.ArgumentParser(prog='tcpdump-parser', add_help=True)

    parser.add_argument('--isrc', help='Source interfaces', nargs='+')
    parser.add_argument('--idst', help='Destination interfaces', nargs='+')

    subparsers = parser.add_subparsers(title='command')

    dump_parser = subparsers.add_parser('dump')

    parse_parser = subparsers.add_parser('parse')
    parse_parser.add_argument('-f', '--srcfile', required=True, help='tcpdump out file')
    parse_parser.add_argument('-d', '--destfile', required=True, help='.xlsx destination file')
    parse_parser.add_argument('-i', '--interval', default=2, help='Capture info about packets from spec interval')
    parse_parser.add_argument('-o', '--orientation', choices=['<', '>'], default=None, help='"<" ">" - orientation')

    return parser


def main(*args):
    parser = __create_argparser()
    opts = parser.parse_args(*args)


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except Exception as ex:
        sys.stderr.write(f'{str(ex)}\n')
        sys.exit(1)
