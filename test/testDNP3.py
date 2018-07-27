import protocols.dnp3

from scapy.sendrecv import sniff
if __name__ == '__main__':
    pcap = sniff(offline="../pcaps/dnp3/assign_class.pcap")
    # pcap.show()
    for i in pcap:
        i.show()
