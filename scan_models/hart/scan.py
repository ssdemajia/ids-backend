from pymongo import MongoClient
from core.utils import convert

module_type_to_key = {
    'hart': 'hart'
}


def hart_resolve(protocol_element):
    info = dict()
    # Todo
    return info


def hart_scan(keys):
    mongo = MongoClient()
    db = mongo.ids
    vul = db.vulnerability
    result = []
    keys = [convert(module_type_to_key, key) for key in keys]
    keys = ' '.join(keys)
    result.extend(vul.find({'$text': {'$search': keys}}))
    return result
