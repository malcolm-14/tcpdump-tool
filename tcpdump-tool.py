import argparse
import sys
import regexp


def __regexp_build(orientation, url):
    pass


def __parse_data(opts):
    timestamp = None

    with open(opts.file) as datafile:
        for line in datafile.readline():
            pass

def cmd_handle(opts):
    if opts.command == 'parse':
        __parse_data(opts)

def __create_argparser():
    parser = argparse.ArgumentParser(prog='tcpdump-parser', add_help=True)

    parser.add_argument('--isrc', help='Source interfaces', nargs='+')
    parser.add_argument('--idst', help='Destination interfaces', nargs='+')

    subparsers = parser.add_subparsers(title='command')
    parse_parser = subparsers.add_parser('parse')
    parse_parser.add_argument('-f', '--srcfile', required=True)
    parse_parser.add_argument('-d', '--destfile', required=True)
    parse_parser.add_argument('-i', '--interval', default=2)
    parse_parser.add_argument('-o', '--orientation', required=True, choices=['<', '>'])

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
