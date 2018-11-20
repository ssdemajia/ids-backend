from pymongo import MongoClient

import os
import re

port = 44818
ip = "166.250.228.16"  # for test
pattern = r'.*{}.*'

module_type_to_key = {
    '1766': 'MicroLogix 1400'
}


def convert(module_type, type_to_key):
    for key in module_type_to_key.keys():
        if key in module_type:
            return module_type_to_key[key]
    return module_type


def ethip_resolve(protocol_element):
    info = dict()
    info['设备IP地址'] = protocol_element.get('Device IP', '')
    info['设备类型'] = protocol_element.get('Device Type', '')
    info['设备名称'] = protocol_element.get('Product Name', '')
    info['设备产品号'] = protocol_element.get('Product Code', '')
    info['校订版本'] = protocol_element.get('Revision', '')
    info['设备序列号'] = protocol_element.get('Serial Number', '')
    info['制造商'] = protocol_element.get('Vendor', '')
    info['profile'] = protocol_element.get('Device Type', '')
    info['key'] = [protocol_element.get('Vendor', ''), ]
    info['key'] = {
        'Vendor': 'Rockwell Automation',
    }
    if '1766' in protocol_element.get('Product Name', ''):
        info['key']['Model'] = 'MicroLogix 1400'
    elif 'logix' in protocol_element.get('Product Name'):
        info['key']['Model'] = 'plc'
    return info


def ethip_scan(keys):
    mongo = MongoClient()
    db = mongo.ids
    vul = db.vulnerability
    result = []
    keys = [convert(key, module_type_to_key) for key in keys]
    keys = ' '.join(keys)
    result.extend(vul.find({'$text': {'$search': keys}}))
    return result


if __name__ == '__main__':
    key = {'Timer/Counter': '8',
           'No. of steps/transitions': '0',
           'For System Use': '\\x08',
           'Controller Model': 'CJ1M_CPU13          04.10',
           'No. DM Words': '32768',
           'Expansion DM Size': '0',
           'Controller Version': '04.10',
           'Memory Card Size': '0',
           'Kind of Memory Card': 'No Memory Card',
           'IOM size': '23',
           'Program Area Size': '40'}
