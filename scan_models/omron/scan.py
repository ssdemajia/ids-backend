from pymongo import MongoClient

import os
import re

port = 9600
ip = "193.252.187.123"  # for test
pattern = r'.*{}.*'

# http://www.ia.omron.com/products/category/automation-systems/programmable-controllers/cp1/index.html


def omron_resolve(protocol_element):
    info = dict()
    info['控制器型号'] = protocol_element.get('Controller Model', '')
    info['控制器版本'] = protocol_element.get('Controller Version', '')
    info['内存卡型号'] = protocol_element.get('Kind of Memory Card', '')
    info['Timer及Counter'] = protocol_element.get('Timer/Counter', '')
    info['程序块大小'] = protocol_element.get('Program Area Size', '')
    info['步进转换数'] = protocol_element.get('No.of steps/trainsitions', '')
    info['profile'] = protocol_element.get('Controller Model', '') + protocol_element.get('Controller Version', '')
    info['key'] = {
        'Vendor': 'omron',
        'Model': protocol_element.get('Controller Model', ''),
        'Version': protocol_element.get('Controller Version', '')
    }
    return info


def omron_scan(keys):
    # Todo
    return []

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
