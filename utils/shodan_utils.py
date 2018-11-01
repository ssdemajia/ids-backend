import shodan
from pymongo import MongoClient

SHODAN_KEY = 'Gqu24TvtvcPR6L4f9840idEpOrXuyWUm'
api = shodan.Shodan(SHODAN_KEY)

mongo = MongoClient()
db = mongo.shodan


def search_shodan(key, collection, parse_func):
    result = api.search(key)
    matches = result['matches']
    db.drop_collection(collection)
    for match in matches:
        result = {}
        data = parse_func(match['data'])
        if len(data) == 0:
            continue
        result['data'] = data
        result['location'] = match['location']
        result['ip'] = match['ip_str']
        print(result)
        db[collection].insert(result)


def parse_s7(info):
    'Copyright: Original Siemens Equipment\nPLC name: n_pod1\nModule type: CPU 313C\nUnknown (129): Boot Loader           A%\nModule: 6ES7 313-5BG04-0AB0  v.0.5\nBasic Firmware: v.3.3.11\nModule name: CPU 313C\nSerial number of module: S C-H4ED79982016\nPlant identification: \nBasic Hardware: 6ES7 313-5BG04-0AB0  v.0.5\n'
    infos = info.split('\n')
    data = {}
    for info in infos:
        if ':' not in info:
            continue
        k, v = info.split(':')
        data[k] = v.strip()
    return data


def parse_modbus(info):
    infos = info.split('\n\n')
    for info in infos:
        if len(info) > 20:
            infos = info
            break
    data = {}
    for info in infos.split('\n'):
        if ':' not in info:
            continue
        if '-- ' in info:
            info = info[info.index('-- ')+3:]
        k, v = info.split(':', 1)
        if len(k) == 0:
            continue
        data[k] = v.strip()
    return data


def parse_bacnet(info):
    infos = info.split('\n')
    data = {}
    for info in infos:
        if ':' not in info:
            continue
        k, v = info.split(':', 1)
        if '.' in k:
            continue
        data[k] = v.strip()
    return data


def parse_ethip(info):
    infos = info.split('\n')
    data = {}
    for info in infos:
        if ':' not in info:
            continue
        k, v = info.split(':', 1)
        if '.' in k:
            continue
        data[k] = v.strip()
    return data


def parse_omron(info):
    infos = info.split('\n')
    data = {}
    for info in infos:
        if ':' not in info:
            continue
        k, v = info.split(':', 1)
        if '.' in k:
            continue
        data[k] = v.strip()
    return data


def get_shodan():
    info = [
        # {
        #     'key': 'Module name: CPU',
        #     'collection': 's7',
        #     'parse func': parse_s7
        # },
        # {
        #     'key': 'Schneider Electric BMX',
        #     'collection': 'modbus',
        #     'parse func': parse_modbus
        # },
        # {
        #     'key': 'Vendor Name: Tridium',
        #     'collection': 'bacnet',
        #     'parse func': parse_bacnet,
        # },
        # {
        #     'key': 'Vendor ID: Rockwell',
        #     'collection': 'ethip',
        #     'parse func': parse_ethip,
        # },
        # {
        #     'key': 'Vendor ID: Rockwell',
        #     'collection': 'ethip',
        #     'parse func': parse_ethip,
        # },
        {
            'key': 'IOM Size:',
            'collection': 'omron',
            'parse func': parse_omron,
        },
    ]
    for i in info:
        search_shodan(i['key'], i['collection'], i['parse func'])
    print('update success')


def get_legel_ips():
    mongo = MongoClient()
    ids = mongo.ids
    ips = list(ids.record.find({}, {'ip': 1}))
    result = [print(ip['ip']) for ip in ips]


if __name__ == '__main__':
    get_legel_ips()


# 82.77.52.152, 78.36.201.246, 5.198.231.44
