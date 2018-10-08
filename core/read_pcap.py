# coding=utf-8
from pyshark import FileCapture
import sys
from io import StringIO

packet2num = {}


class PcapReader:
    def __init__(self, filename, summary=True, keep_packets=False):
        self.result = []
        self.cap = FileCapture(filename, only_summaries=summary, keep_packets=keep_packets)
        if filename in packet2num:
            self.length = packet2num[filename]
        else:
            self.length = self.packet_length()

    def packet_length(self):
        length = [0]

        def decode(packet):
            length[0] += 1
        self.cap.apply_on_packets(decode)
        return length[0]

    def get_specify(self, start, end):
        # page split
        def decode(packet):
            item = {
                "id": packet.no,
                "src": packet.source,
                "dst": packet.destination,
                "time": round(float(packet.time), 5),
                "protocol": packet.protocol,
                "info": packet.info,
                "length": packet.length
            }
            self.result.append(item)
        for index in range(start, end):
            pack = self.cap[index-1]
            decode(pack)
        return self.result, self.length

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
    import os
    filename = 'Modbus.pcap'
    filename = '4SICS-GeekLounge-151020.pcap'
    path = '/home/ss/Desktop/project-backend/ids-backend/upload/' + filename
    print(path)
    # reader = PcapReader('./upload/DNP3-RequestLink.pcap', summary=False, keep_packets=True)
    # reader = PcapReader('./upload/s7comm_downloading_block_db1.pcap')
    # reader = PcapReader('./upload/s7-1200-hmi.pcap', summary=False, keep_packets=True)
    reader = PcapReader(path, summary=True, keep_packets=True)
    # reader = PcapReader('./upload/s7comm_reading_setting_plc_time.pcap')
    # reader = PcapReader('./upload/4SICS-GeekLounge-151020.pcap')
    # info = reader.get_detail(1)
    info = reader.get_specify(1, 5)
    # reader.process_packet()
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