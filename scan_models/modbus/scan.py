from pymongo import MongoClient

import os
import re

port = 502
ip = "166.139.80.97"  # for test
nse_path = os.path.join(os.getcwd(), '..', 'nse')
pattern = r'.*{}.*'


module_type_to_key = {
    'BMX': 'BMX P34'
}


def convert(module_type, type_to_key):
    for key in type_to_key.keys():
        if key in module_type:
            return type_to_key[key]
    return module_type


def modbus_resolve(protocol_element):
    info = dict()

    info['CPU模块'] = protocol_element.get('CPU Module', '')
    info['固件版本'] = protocol_element.get('Firmware', '')
    info['内存卡'] = protocol_element.get('Memory Card', '')
    info['网络模块'] = protocol_element.get('Network Module', '')
    info['项目信息'] = protocol_element.get('Project information', '')
    info['项目上次修改时间'] = protocol_element.get('Project Last Modified', '')
    info['项目修订版本'] = protocol_element.get('Project Revision', '')
    info['制造商信息'] = protocol_element.get('Vendor Name', '')
    info['profile'] = protocol_element.get('Vendor Name', '') + ',' + protocol_element.get('CPU Module', '')
    info['key'] = [protocol_element.get('Vendor Name', ''), protocol_element.get('CPU Module', '')]

    info['key'] = {
        'CPU Module': protocol_element.get('System Name', ''),
        'Vendor Name': protocol_element.get('Vendor Name', ''),
        'Version': protocol_element.get('Firmware', '')
    }
    if 'BMX'.lower() in info['CPU模块'].lower():
        info['产品系列'] = 'Modicon M340'
        info['key']['Category'] = 'm340'
    elif '140' in info['CPU模块'].lower():
        info['产品系列'] = 'Modicon Premium'
        info['key']['Category'] = 'premium'
    elif 'TSX'.lower() in info['CPU模块'].lower():
        info['产品系列'] = 'Modicon Quantum'
        info['key']['Category'] = 'quantum'
    # https://www.schneider-electric.com/en/product-category/5100-software?filter=business-1-industrial-automation-and-control&parent-category-id=5100&parent-subcategory-id=5150
    return info


def modbus_scan(keys):
    mongo = MongoClient()
    db = mongo.ids
    vul = db.vulnerability
    result = []
    keys = [convert(key, module_type_to_key) for key in keys]
    keys = ' '.join(keys)
    result.extend(vul.find({'$text': {'$search': keys}}))
    return result


if __name__ == '__main__':
    key = {
        'CPU Module': 'BMX P34 2020',
        'Vendor Name': 'Schneider Electric  ',
        'Category': 'M340'
    }
    print(len(modbus_scan(key)))
