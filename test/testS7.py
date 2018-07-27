import protocols.cotp
import protocols.cip
import protocols.s7comm
from scapy.sendrecv import sniff
if __name__ == '__main__':
    pcap = sniff(offline="../pcaps/s7comm/s7comm_downloading_block_db1.pcap")
    for i in pcap:
        i.show()
