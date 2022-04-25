from scapy.all import *

import argparse

from scapy.layers.inet import IP, TCP


def check_port_range(host, start, end, **kwargs):
    sr(IP(dst=host) / TCP(sport=RandShort(), dport=(start, end), flags="S"), **kwargs)[0].summary(lfilter = lambda s,r: "SA" in r.sprintf("%TCP.flags%"),prn=lambda s,r: r.sprintf("%TCP.sport%"))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="scapy scan tool",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("host", help="host ip address")
    parser.add_argument("-s", "--start", type=int, help="port range start")
    parser.add_argument("-e", "--end", type=int, help="port range end")
    parser.add_argument("-t", "--timeout", type=int, default=2, help="timeout in seconds")
    parser.add_argument("-r", "--retry", type=int, default=-1, help="if positive, number of retries until response. if negative, number of retries without answer.")
    parser.add_argument("-v", "--verbose", type=int, default=1,  help="verbosity level of scapy api")
    parser.add_argument("-c", "--chunk_size", type=int, default=150, help="chunk size of port ranges to be checked at once")
    args = parser.parse_args()
    config = vars(args)
    print(config)
    #check_port_range_(args.host, int(args.start), int(args.end), int(args.timeout))
    end = args.start - 1
    while end < args.end:
        start = end + 1
        end = min(args.end, start + args.chunk_size - 1)
        if args.verbose > 0:
            print(f"checking {start}-{end}")
        check_port_range(args.host, start, end, timeout=args.timeout, retry=args.retry, verbose=args.verbose)
