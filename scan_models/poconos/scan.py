from pymongo import MongoClient

import os
import re

port = 44818
ip = "166.250.228.16"  # for test
pattern = r'.*{}.*'


def proconos_resolve(protocol_element):
    info = dict()
    info['固件版本'] = protocol_element.get('Fireware Version', '')
    info['固件日期'] = protocol_element.get('Fireware Date', '')
    info['固件时间'] = protocol_element.get('Fireware Time', '')
    info['设备序列号'] = protocol_element.get('Model Number', '')
    info['PLC 型号'] = protocol_element.get('PLC Type', '')
    info['profile'] = 'ProConOS ' + protocol_element.get('Fireware Version', '')
    info['key'] = ['proconos']
    info['key'] = {
        'Model': protocol_element.get('PLC Type', ''),
    }
    return info


def proconos_scan(keys):
    mongo = MongoClient()
    db = mongo.ids
    vul = db.vulnerability
    model = keys['Model']
    if 'ILC'.lower() in model:
        model = 'ILC'
    vendor = 'Phoenix'
    result = []
    result.extend(vul.find({'title': re.compile(pattern.format(model), re.IGNORECASE),
                            'product': re.compile(pattern.format(vendor), re.IGNORECASE)}))

    return result


if __name__ == '__main__':
    # https://www.phoenixcontact.com/online/portal/us/pxc/product_list_pages/!ut/p/z1/vVRNb8IwDP01HKM4aVLaY-nQ2AQbDBi0lyptUwjqF22AsV-_Fk47jGqaWBQpjhU_51l-xj5eYz8XR7URWhW5SJu755vBYrAYDqfUJK8zPoCnB-4Ox-yNjMYMv2Mf-1GuS73F3qGWeQ9OMuxBJlRjllURHyJd9yBVtQ5KsZH1xbupRJaJMJVBVOS6KtJUVnVQIkoQtLsHccKooLGNEs4oYjxmyALDQIQnQE0uhRGFbe4yUjH2LAKSUZOixJQ2YpZlIIv0KeI0TPoJBU6ljVc3yTgE-7e5XuPhh-VAV7zXxPcD-kiAjBiZPHLTgplLxy_Gw9DpE8Cro5InvMyLKmtqP_8lvRF0ZaB_zNABT-4KP7ovvH3f4tjGXeGnf_39c1fzNpNA7fZ732nk3khWfmi8_ne9r1pWHRq-PLgh0rnMg-U8mK7d5byr5eBaR5WVqYqUnhSxTLGnq4Ns3SJqpyT2aimqaHsZDzexyiyzjLNC3vPxdFokmRta34-zATsmws_k7HwBRzPsNw!!/#Z7_2G101H41MG5680QC2LN3DEA7H0
    key = {'Firmware Date': 'Mar  2 2012',
           'PLC Type': 'ILC 330 ETH',
           'Firmware Version': '3.95T',
           'Firmware Time': '09:39:02',
           'Model Number': '2737193'}
