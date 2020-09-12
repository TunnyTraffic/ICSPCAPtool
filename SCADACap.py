import argparse
import os
import sys
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
import scapy.contrib.modbus as scmb
from collections import Counter

#class ModBusPDU:
#    def __init__(self, rawdata):
#        self.rawdata = rawdata







def process_pcap(file_name):
    print('Opening {}...'.format(file_name))

    count = 0
    interesting_packet_count = 0
    sources = []
    destinations = []

    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
        count += 1

        ether_pkt = Ether(pkt_data)
        if 'type' not in ether_pkt.fields:
            # LLC frames will have 'len' instead of 'type'.
            # We disregard those
            continue

        if ether_pkt.type != 0x0800:
            # disregard non-IPv4 packets
            continue

        ip_pkt = ether_pkt[IP]
        if ip_pkt.proto != 6:
            # Ignore non-TCP packet
            continue

        # print(ip_pkt.summary())


        source = ip_pkt.fields['src']
        destination = ip_pkt.fields['dst']
        payload = ip_pkt[TCP].payload
        sources.append(source)
        destinations.append(destination)

        print('Source: ', source)
        print('Destination: ', destination)

        print('Raw payload: ',bytes(payload))

        modbuspacket = scmb.ModbusAD
        #    function_code = scmb.orb(ip_pkt[TCP].payload[0])
        print(function_code)

        #print(ip_pkt[0].show()) #this one shows everything for debugging

        interesting_packet_count += 1

    print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')

    s = Counter(sources)
    d = Counter(destinations)
    print('Source counts: ',s)
    print('Destination counts: ',d)
    print('{} contains {} packets ({} interesting)'.
          format(file_name, count, interesting_packet_count))



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcap', metavar='<pcap file name>',
                        help='pcap file to parse', required=True)
    args = parser.parse_args()

    file_name = args.pcap
    if not os.path.isfile(file_name):
        print('"{}" does not exist'.format(file_name), file=sys.stderr)
        sys.exit(-1)

    process_pcap(file_name)
    sys.exit(0)