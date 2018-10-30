from pymongo import MongoClient
from multiprocessing import Pool
from core.vul_scan import get_system_info
from core.utils import get_loc

import os
import time

RETRY_TIMES = 5
nse_path = os.path.join(os.getcwd(), '..', 'nse')


def get_ips():
    collections = ['bacnet', 'ethip', 'modbus', 'omron', 's7']
    mongo = MongoClient()
    shodan = mongo.shodan

    ids = mongo.ids
    ids.drop_collection('ip')
    for collect in collections:
        records = list(shodan[collect].find())
        for record in records:
            print(record['ip'])
            ids.ip.insert({'ip': record['ip']})


def scan_ip(ip):
    ip = ip['ip']
    mongo = MongoClient()
    ids = mongo.ids
    has_ip = ids.record.find({'ip': ip})
    if len(list(has_ip)) != 0:
        print(ip, 'has scan')
        return
    info = get_system_info(ip, nse_path)
    if info is None or len(info) == 0:
        return
    address = get_loc(ip)
    if address is None:
        for retry in range(RETRY_TIMES):
            time.sleep(retry)
            address = get_loc(ip)
            if address is not None:
                break
    if address is None:
        return
    info['longitude'], info['latitude'], info['address'] = address
    info['vulnerability'] = []
    info['ip'] = ip
    ids.record.insert(info)
    print(info)


def scan_ips():
    mongo = MongoClient()
    ids = mongo.ids
    # ids.drop_collection('record')
    ips = list(ids.ip.find())
    pool = Pool()
    pool.map(scan_ip, ips)


if __name__ == '__main__':
    scan_ips()
