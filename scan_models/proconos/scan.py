from pymongo import MongoClient
from core.utils import convert

module_type_to_key = {
    'proconos': 'proconos'
}


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
    result = []
    keys = [convert(module_type_to_key, key) for key in keys]
    keys = ' '.join(keys)
    result.extend(vul.find({'$text': {'$search': keys}}))
    return result
