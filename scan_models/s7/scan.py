from pymongo import MongoClient

import os
import re

port = 102
ip = '140.206.150.51'  # for test
nse_path = os.path.join(os.getcwd(), '..', 'nse')
pattern = r'.*{}.*'

module_type_to_key = {
    'IM151': 'ET200'
}


def convert(module_type, type_to_key):
    for key in module_type_to_key.keys():
        if key in module_type:
            return module_type_to_key[key]
    return module_type


def s7_resolve(elements):
    info = dict()
    info['硬件信息'] = elements.get('Basic Hardware', '')
    info['系统名称'] = elements.get('System Name', '')
    info['信息版权'] = elements.get('Copyright', '')
    info['版本号'] = elements.get('Version', '')
    info['模块'] = elements.get('Module Type', '')
    info['序列号'] = elements.get('Serial Number', '')
    info['模块型号'] = elements.get('Module', '')
    info['profile'] = elements.get('System Name', '')

    info['key'] = [elements.get('Module Type', '')]
    return info


def s7_scan(keys):
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
        'System Name': 'SIMATIC 300 Station',
        'Copyright': 'Original Siemens Equipment',
        'Version': '3.3.2'
    }
    print(len(s7_scan(key)))
