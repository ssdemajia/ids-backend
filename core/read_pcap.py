# coding=utf-8
from pyshark import FileCapture
import sys
from io import StringIO


class PcapReader:
    def __init__(self, filename, summary=True, keep_packets=False):
        self.result = []
        self.cap = FileCapture(filename, only_summaries=summary, keep_packets=keep_packets)

    def process_packet(self):
        def decode(packet):
            item = {
                "id": packet.no,
                "src": packet.source,
                "dst": packet.destination,
                "time": packet.time,
                "protocol": packet.protocol,
                "info": packet.info,
                "length": packet.length
            }
            self.result.append(item)
        self.cap.apply_on_packets(decode)

    def get_specify(self):
        self.process_packet()
        return self.result

    def get_detail(self, id):
        packet = self.cap[id-1]
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        packet.pretty_print()
        sys.stdout = old_stdout
        info = mystdout.getvalue()
        detail = []
        index = -1
        # packet.pretty_print()
        for line in info.split('\n'):
            if "Layer" in line:
                index += 1
                detail.append({
                    'layer': line,
                    'fields': []
                })
                continue
            if line.strip() in detail[index]['fields']:
                continue
            detail[index]['fields'].append(line.strip())
        return detail

    def close(self):
        self.cap.clear()
        self.cap.close()
if __name__ == '__main__':
    # reader = PcapReader('./upload/DNP3-RequestLink.pcap', summary=False, keep_packets=True)
    # reader = PcapReader('./upload/s7comm_downloading_block_db1.pcap')
    # reader = PcapReader('./upload/s7-1200-hmi.pcap', summary=False, keep_packets=True)
    reader = PcapReader('./upload/omron.pcap', summary=False, keep_packets=True)
    # reader = PcapReader('./upload/s7comm_reading_setting_plc_time.pcap')
    # reader = PcapReader('./upload/4SICS-GeekLounge-151020.pcap')
    info = reader.get_detail(1)
    # detail = []
    # index = -1
    # current_layer = ""
    # for line in info.split('\n'):
    #     if "Layer" in line:
    #         index += 1
    #         current_layer = line
    #         detail.append({
    #             'layer': line,
    #             'fields': []
    #         })
    #         continue
    #     detail[index]['fields'].append(line)
    print(info)