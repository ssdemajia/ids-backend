from pymongo import MongoClient
from multiprocessing import Pool
from core.vul_scan import get_system_info, vul_scan
from core.utils import get_loc, calculate_safety
from datetime import datetime

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


def scan_all_system():
    mongo = MongoClient()
    shodan = mongo.shodan
    collection = shodan.all
    from pprint import pprint
    result = list(collection.find())
    for info in result:
        data = info['data']
        print(info['type'])
        if info['type'] == 'omron':
            key = [data.get('Controller Model', '')]
            port = 9600
        elif info['type'] == 's7':
            key = [data.get('Module type', ''),
                   data.get('Version', '')]
            port = 102
        elif info['type'] == 'bacnet':
            key = [data.get('Model Name', '')]
            port = 47808
        elif info['type'] == 'modbus':
            key = [data.get('CPU module', '')]
            port = 502
        elif info['type'] == 'ethip':
            key = [data.get('Product name'), '']
            port = 44818
        elif info['type'] == 'melsec':
            key = ['melsec', '']
            port = 5007
        elif info['type'] == 'redlion':
            key = ['redlion', '']
            port = 789
        elif info['type'] == 'proworx':
            key = ['proworx', '']
            port = 1962
        elif info['type'] == 'proconos':
            key = ['proconos', '']
            port = 20547
        elif info['type'] == 'iec104':
            key = ['iec104', '']
            port = 2404
        elif info['type'] == 'hart':
            key = ['hart', '']
            port = 5094
        elif info['type'] == 'niagara':
            key = ['niagara', '']
            port = 1911
        elif info['type'] == 'dnp3':
            key = ['dnp3', '']
            port = 20000
        elif info['type'] == 'codesys':
            key = ['codesys', '']
            port = 2455
        vuls = vul_scan(key, port)
        info['vuls'] = vuls
        collection.update_one({'_id': info['_id']}, {'$set': {'vuls': vuls}})
        pprint(len(vuls))
        pprint(info)


def scan_all_system_distribute():
    mongo = MongoClient()
    shodan = mongo.shodan
    all = shodan.all
    distribute = shodan.distribute
    system_types = ['', 's7', 'ethip', 'modbus', 'bacnet', 'omron', 'melsec', 'redlion', 'proconos''proworx', 'iec104', 'hart', 'niagara', 'dnp3', 'codesys']
    for system_type in system_types:
        distribute.update({'type': system_type}, {'type': system_type}, upsert=True)
        result = {
            '高危': 0,
            '中危': 0,
            '低危': 0,
            '健康': 0
        }
        if system_type == '':
            vuls = all.find({}, {'vuls': 1})
        else:
            vuls = all.find({'type': system_type}, {'vuls': 1})
        for vul in vuls:
            result[calculate_safety(vul['vuls'])] += 1

        shodan.distribute.update({'type': system_type}, {'$push': {'date': datetime.now(), 'result': result}})


if __name__ == '__main__':
    scan_all_system_distribute()
    # scan_all_system()