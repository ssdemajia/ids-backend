from pymongo import MongoClient
from config import SHODAN_KEY
import shodan
import time

api = shodan.Shodan(SHODAN_KEY)

mongo = MongoClient()
db = mongo.shodan


def search_shodan(key, collection, parse_func):
    db.drop_collection(collection)
    result = api.search(key, page=1)
    total = result['total']
    pages = total // 100 + 1
    parse(result, collection, parse_func)
    for page in range(2, pages):
        time.sleep(1)
        try:
            result = api.search(key, page=page)
        except shodan.exception.APIError:
            time.sleep(3)
            result = result = api.search(key, page=page)
        parse(result, collection, parse_func)


def parse(result, collection, parse_func):
    matches = result['matches']

    for match in matches:
        try:
            result = {}
            data = parse_func(match['data'])

            if len(data) == 0:
                continue
            result['data'] = data
            result['location'] = match['location']
            result['ip'] = match['ip_str']
            result['type'] = collection
            print(result)
            db[collection].insert(result)
            db['all'].insert(result)
        except Exception:
            continue


def parse_s7(info):
    'Copyright: Original Siemens Equipment\nPLC name: n_pod1\nModule type: CPU 313C\nUnknown (129): Boot Loader           A%\nModule: 6ES7 313-5BG04-0AB0  v.0.5\nBasic Firmware: v.3.3.11\nModule name: CPU 313C\nSerial number of module: S C-H4ED79982016\nPlant identification: \nBasic Hardware: 6ES7 313-5BG04-0AB0  v.0.5\n'
    infos = info.split('\n')
    data = {}
    try:
        for info in infos:
            if ':' not in info:
                return data
            k, v = info.split(':')
            data[k] = v.strip()
    except Exception:
        return {}
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


def parse_dnp3(info):
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


def parse_niagara(info):
    """
    fox a 0 -1 fox hello
    {
        fatal=s:Niagara4 Station Connections Unsupported
        fox.version=s:Niagara 4
    };;
    """
    infos = info.split('\n')
    data = {}
    left_bracket = -1
    right_bracket = -1
    for index in range(len(infos)):  # find the range from '{' to '}'
        if '{' in infos[index]:
            left_bracket = index
        elif '}' in infos[index]:
            right_bracket = index

    if left_bracket == -1 or right_bracket == -1:
        return data
    for info in infos[left_bracket+1: right_bracket]:
        if '=' not in info:
            continue
        k, v = info.split('=', 1)
        if '.' in k:
            k = k[k.index('.')+1:]
        if ':' in v:
            v = v[2:]
        if '[' in k:
            continue
        data[k] = v.strip()
    return data


def parse_hart(info):
    """
    HART-IP Gateway
    """
    return {
        'info': info
    }


def parse_pcworx(info):
    """
    PLC Type: ILC 130 ETH
    Model Number: 2988803
    Firmware Version: 3.91
    Firmware Date: 11/23/11
    Firmware Time: 14:15:00      
    """
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


def parse_melsec(info):
    """
    CPU: Q06UDEHCPU      j          X
    """
    data = {}
    if 'CPU' not in info:
        return data
    if len(info) < 6:
        return data
    data['CPU'] = info[5]
    return data


def parse_redlion(info):
    """
    Manufacturer: Red Lion Controls
    Model: MC6B
    """
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


def parse_codesys(info):
    """
    Operating System: Nucleus PLUS
    Operating System Details: Nucleus PLUS version unknown
    Product: 3S-Smart Software Solutions
    """
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


def parse_iec104(info):
    """
    Data Received: 680e1a00020064014600ffff00000000
    ASDU Address: 65535
    """
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


def parse_proconos(info):
    """
    Ladder Logic Runtime: ProConOS V4.1.0230 Feb  4 2011
    PLC Type: Bristol: CLM V05:40:00 02/04
    Project Name: NGC_ELK
    Boot Project:
    Project Source Code:
    """
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
        {
            'key': 'Module name: CPU',
            'collection': 's7',
            'parse func': parse_s7
        },
        {
            'key': 'Schneider Electric BMX',
            'collection': 'modbus',
            'parse func': parse_modbus
        },
        {
            'key': 'Vendor Name: Tridium',
            'collection': 'bacnet',
            'parse func': parse_bacnet,
        },
        {
            'key': 'Vendor ID: Rockwell',
            'collection': 'ethip',
            'parse func': parse_ethip,
        },
        {
            'key': 'IOM Size:',
            'collection': 'omron',
            'parse func': parse_omron,
        },
        {
            'key': 'port:20000 source address',
            'collection': 'dnp3',
            'parse func': parse_dnp3,
        },

        # {
        #     'key': 'port:1911,4911 product:Niagara',
        #     'collection': 'niagara',
        #     'parse func': parse_niagara
        # },
        # {
        #     'key': 'port:5094 hart-ip',
        #     'collection': 'hart',
        #     'parse func': parse_hart
        # },
        # {
        #     'key': 'port:1962 PLC',
        #     'collection': 'pcworx',
        #     'parse func': parse_pcworx
        # },
        # {
        #     'key': 'port:5006,5007 product:mitsubishi',
        #     'collection': 'melsec',
        #     'parse func': parse_melsec
        # },
        # {
        #     'key': 'port:789 product:"Red Lion Controls"',
        #     'collection': 'redlion',
        #     'parse func': parse_redlion
        # },
        # {
        #     'key': 'port:2455 operating system',
        #     'collection': 'codesys',
        #     'parse func': parse_codesys
        # },
        # {
        #     'key': 'port:2404 asdu address',
        #     'collection': 'iec104',
        #     'parse func': parse_iec104
        # },
        # {
        #     'key': 'port:20547 PLC',
        #     'collection': 'proconos',
        #     'parse func': parse_proconos
        # },
    ]

    # db.drop_collection('all')
    for i in info:
        search_shodan(i['key'], i['collection'], i['parse func'])
    print('update success')


def get_legel_ips():
    mongo = MongoClient()
    ids = mongo.ids
    ips = list(ids.record.find({}, {'ip': 1}))
    result = [print(ip['ip']) for ip in ips]


if __name__ == '__main__':
    get_shodan()


# 82.77.52.152, 78.36.201.246, 5.198.231.44
