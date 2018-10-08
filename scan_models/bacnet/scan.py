from pymongo import MongoClient
from .. import vendors, get_vendor
import os
import re

port = 47808
ip = "24.248.68.156"  # for test
pattern = r'.*{}.*'



def bacnet_resolve(protocol_element):
    info = dict()
    info['型号'] = protocol_element.get('Model Name', '')
    info['目标名称'] = protocol_element.get('Object Name', '')
    info['目标ID'] = protocol_element.get('Object ID', '')
    info['固件版本'] = protocol_element.get('Firmware', '')
    info['制造商'] = protocol_element.get('Vendor ID', '') + protocol_element.get('Vendor Name', '')
    info['信息'] = protocol_element.get('Description', '')
    info['profile'] = protocol_element.get('Model Name', '')
    info['key'] = {
        'Protocol': 'bacnet',
        'Vendor ID': protocol_element.get('Vendor ID', ''),
        'Version': protocol_element.get('Firmware', '')
    }
    return info


def bacnet_scan(keys):
    mongo = MongoClient()
    db = mongo.ids
    vul = db.vulnerability
    vendor_key = keys['Vendor ID']
    result = []
    vendor = get_vendor(vendor_key)
    if vendor == '':
        return []
    result.extend(vul.find({'title': re.compile(pattern.format('bacnet'), re.IGNORECASE),
                            'product': re.compile(pattern.format(vendor), re.IGNORECASE)}))
    return result


if __name__ == '__main__':
    key = {
        'Protocol': 'bacnet',
        'Vendor ID': 'siemens',
        'Version': '9.0.0.4256'
    }
    print(bacnet_scan(key))