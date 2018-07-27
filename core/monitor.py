# coding=utf-8
import threading
from pyshark import LiveCapture
from bson import ObjectId
from pymongo import MongoClient
from flask.json import JSONEncoder


class MonitorJsonEncoder(JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        elif isinstance(o, bytes):
            return o.decode('utf-8')
        return json.JSONEncoder.default(self, o)


class Monitor(threading.Thread):
    def __init__(self, interface):
        super(Monitor, self).__init__()
        self.running = True
        self.interface = interface
        self.client = MongoClient()
        self.db = self.client.ids
        self.packet = self.db.packet

    def run(self):
        self.cap = LiveCapture(self.interface, only_summaries=True)
        while self.running:
            packets = self.cap.sniff_continuously(packet_count=10)
            self.process_packet(packets)

    def stop(self):
        self.running = False
        self.db.drop_collection('packet')
        self.cap.close()

    def process_packet(self, packets):
        temp = []
        for packet in packets:
            item = {
                "id": int(packet.no),
                "src": packet.source,
                "dst": packet.destination,
                "time": packet.time,
                "protocol": packet.protocol,
                "info": packet.info,
                "length": packet.length
            }
            temp.append(item)
        self.packet.insert(temp)

    def __del__(self):
        self.cap.clear()
        self.cap.close()


if __name__ == '__main__':
    inter = "enp3s0"
    monitor = Monitor(inter)
    # monitor.run()
    from flask import jsonify
    import json
    print(json.dumps(list(monitor.packet.find({"id": {"$gt": 230}})), cls=MonitorJsonEncoder))