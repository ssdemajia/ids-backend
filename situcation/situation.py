from flask import Blueprint, request, jsonify
from pymongo import MongoClient
from core.monitor import MonitorJsonEncoder
from core.utils import calculate_safety


import re
import json
import datetime
import itertools

situation = Blueprint('situation', __name__)
mongo = MongoClient()


@situation.route('/device', methods=["POST"])
def get_device_info():
    data = request.get_json()
    device_type = data['type']

    infos = mongo.shodan[device_type].find()
    result = {
        'code': 20000,
        'result': list(infos),
        'name': device_type
    }
    response = json.dumps(result, cls=MonitorJsonEncoder)
    return response


@situation.route('/vuls_count')
def get_vuls_count():
    querys = ['', r'高', r'中', r'低']
    result = []
    for query in querys:
        reg = re.compile(query)
        result.append(mongo.ids.vulnerability.find({'level': reg}).count())
    return jsonify({
        'code': 20000,
        'result': result
    })


def merge(all_date, current_date):
    index = 1
    temp = []
    for date in all_date:
        if index < len(current_date) and date >= current_date[index][0]:
            temp.append(current_date[index][1])
            index += 1
        else:
            temp.append(0)
    return temp


@situation.route('/vuls_distribution')
def get_vuls_distribution():
    def group(vul_date):
        rp = vul_date.rindex('-')
        p = vul_date.index('-')
        return int(vul_date[:p]+ vul_date[p+1:rp])

    querys = [r'', r'高', r'中', r'低']
    result = []
    for query in querys:
        reg = re.compile(query)
        vuls = mongo.ids.vulnerability.find({'level': reg})
        format_vul = [vul['submit_date'] for vul in vuls if re.match(r'\d*-\d*-\d*', vul['submit_date']) is not None]
        temp = []
        format_vul.sort(key=group)
        for i, k in itertools.groupby(format_vul, group):
            temp.append([i, len(list(k))])
        result.append(temp)

    all_date = [date for date, _ in result[0]]

    for i in range(1, len(result)):
        result[i] = merge(all_date, result[i])
    result[0] = all_date

    return jsonify({
        'code': 20000,
        'result': result
    })


@situation.route('/vuls', methods=["POST"])
def get_vuls_by_key():
    data = request.get_json()
    key = data['key']
    reg = re.compile(key, re.IGNORECASE)
    vuls = mongo.ids.vulnerability.find({'product': reg}).limit(20)
    result = json.dumps({
        'code': 20000,
        'result': list(vuls)
    }, cls=MonitorJsonEncoder)
    return result


@situation.route('/system_info', methods=["POST"])
def get_system_info():
    data = request.get_json()
    ip = data['ip']
    info = mongo.shodan.all.find_one({'ip': ip})
    result = json.dumps({
        'code': 20000,
        'result': info
    }, cls=MonitorJsonEncoder)
    return result


@situation.route('/system_vuls', methods=['POST'])
def get_system_vuls():
    data = request.get_json()
    ip = data['ip']
    info = mongo.shodan.all.find_one({'ip': ip})
    result = json.dumps({
        'code': 20000,
        'result': info
    }, cls=MonitorJsonEncoder)
    return result




@situation.route('/system_score')
def get_system_score():
    systems = mongo.shodan.all.find({}, {'vuls': 1})
    result = {
        '高危': 0,
        '中危': 0,
        '低危': 0,
        '健康': 0
    }
    for system in systems:
        result[calculate_safety(system['vuls'])] += 1
    result = json.dumps({
        'code': 20000,
        'result': result
    }, cls=MonitorJsonEncoder)
    return result


@situation.route('/system_vuls_count', methods=["POST"])
def get_system_vuls_count():
    data = request.get_json()
    sys_type = data['type']
    if sys_type == '':
        systems = mongo.shodan.all.find({}, {'vuls': 1})
    else:
        systems = mongo.shodan.all.find({'type': sys_type}, {'vuls': 1})
    result = {
        '高危': 0,
        '中危': 0,
        '低危': 0,
        '健康': 0
    }
    for system in systems:
        result[calculate_safety(system['vuls'])] += 1
    result = json.dumps({
        'code': 20000,
        'result': result
    }, cls=MonitorJsonEncoder)
    return result


@situation.route('/system_vuls_distribute', methods=["POST"])
def get_system_vuls_distribute():
    data = request.get_json()
    sys_type = data['type']
    systems = mongo.shodan.distribute.find_one({'type': sys_type})
    result = json.dumps({
        'code': 20000,
        'result': systems
    }, cls=MonitorJsonEncoder)
    return result

