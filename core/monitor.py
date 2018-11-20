# coding=utf-8
import threading
from pyshark import LiveCapture
from bson import ObjectId
from pymongo import MongoClient
from flask.json import JSONEncoder

import json
import datetime

class MonitorJsonEncoder(JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return
        elif isinstance(o, bytes):
            return o.decode('utf-8')
        elif isinstance(o, datetime.datetime):
            return o.__str__()
        return json.JSONEncoder.default(self, o)


class Monitor(threading.Thread):
    def __init__(self, interface, count):
        super(Monitor, self).__init__()
        self.interface = interface
        self.count = count
        self.client = MongoClient()
        self.db = self.client.ids
        self._packet = self.db.packet
        self.packet_id = 0

    def run(self):
        self.db.drop_collection('packet')
        self._packet = self.db.packet
        self._cap = LiveCapture(self.interface, only_summaries=True)
        count_per_sniff = 30
        if self.count < count_per_sniff:
            count_per_sniff = self.count
        while self.count > 0:
            import sys
            print(self.count, file=sys.stderr)
            packets = self._cap.sniff_continuously(packet_count=count_per_sniff)
            self.count -= count_per_sniff
            self.process_packet(packets)

    def process_packet(self, packets):
        temp = []
        for packet in packets:
            # print(packet)
            item = {
                "id": self.packet_id,
                "src": packet.source,
                "dst": packet.destination,
                "time": packet.time,
                "protocol": packet.protocol,
                "info": packet.info,
                "length": packet.length
            }
            self.packet_id += 1
            temp.append(item)
        self._packet.insert(temp)

    def __del__(self):
        self._cap.clear()
        self._cap.close()
        self.client.close()


if __name__ == '__main__':
    inter = "enp3s0"
    monitor = Monitor(inter, 1000)
    monitor.run()
    from flask import jsonify
    import json
    print(json.dumps(list(monitor._packet.find()), cls=MonitorJsonEncoder))