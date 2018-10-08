from pymongo import MongoClient

import os
import re

port = 102
ip = '140.206.150.51'  # for test
nse_path = os.path.join(os.getcwd(), '..', 'nse')
pattern = r'.*{}.*'


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
    info['key'] = {
        'System Name': elements.get('System Name', ''),
        'Copyright': elements.get('Copyright', ''),
        'Version': elements.get('Version', '')
    }

    return info


def s7_scan(keys):
    mongo = MongoClient()
    db = mongo.ids
    vul = db.vulnerability
    num_reg = r'(\d+[./-]*\d*)'
    result = []
    if 'System Name' not in keys or len(keys['System Name']) == 0:
        return []
    product_num = re.findall(num_reg, keys['System Name'])  # find s7 300
    if len(product_num) == 0:
        product_num = ""
    else:
        product_num = product_num[0]
    result.extend(vul.find({'product': re.compile(pattern.format(product_num), re.IGNORECASE),
                            'link': re.compile(pattern.format('siemens'), re.IGNORECASE)}))
    return result


if __name__ == '__main__':
    key = {
        'System Name': 'SIMATIC 300 Station',
        'Copyright': 'Original Siemens Equipment',
        'Version': '3.3.2'
    }
    print(len(s7_scan(key)))
