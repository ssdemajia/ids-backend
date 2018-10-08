from flask import Blueprint, request, jsonify, make_response
from core.vul_scan import get_result, vul_scan
from pymongo import MongoClient
from core.monitor import MonitorJsonEncoder

import json
import os

nse_path = os.path.join(os.getcwd(), 'nse')

vulnerability = Blueprint('vul', __name__)


# vulnerability
@vulnerability.route('/scanner', methods=["POST"])
def get_system_info():
    data = request.get_json()
    if "ip" not in data:
        return jsonify({
            'code': 50004,
            'result': "invalid ip address"
        })
    ip = data['ip']
    # info = get_result(ip, nse_path)
    info = {
        "key": {
            "Copyright": "Original Siemens Equipment",
            "System Name": "SIMATIC 300 Station",
            "Version": "3.3.2"
        },
        "port": 102,
        "profile": "SIMATIC 300 Station",
        "信息版权": "Original Siemens Equipment",
        "序列号": "S C-BDU433522011",
        "模块": "CPU 314",
        "模块型号": "6ES7 314-1AG14-0AB0 ",
        "版本号": "3.3.2",
        "硬件信息": "6ES7 314-1AG14-0AB0 ",
        "系统名称": "SIMATIC 300 Station"
    }
    return jsonify({
        'code': 20000,
        'result': info
    })


@vulnerability.route('/scan', methods=['POST'])
def scan_by_key():
    data = request.get_json()
    if "info" not in data:
        return jsonify({
            'code': 50004,
            'result': "invalid ip address"
        })
    info = data['info']
    result = vul_scan(info)

    result = {
        'code': 20000,
        'result': result
    }
    result = json.dumps(result, cls=MonitorJsonEncoder)
    response = make_response(result)
    response.headers['Content-Type'] = 'application/json'
    return response


@vulnerability.route('/list', methods=['POST'])
def get_vulnerability():
    data = request.get_json()
    start = int(data['start'])
    end = int(data['end'])
    mongo = MongoClient()
    db = mongo.ids
    vulner = db.vulnerability
    cursor = vulner.find().limit(end - start).skip(start)
    result = list(cursor)
    cursor = vulner.find().count()
    result = {
        'code': 20000,
        'result': result,
        'count': cursor
    }
    result = json.dumps(result, cls=MonitorJsonEncoder)
    response = make_response(result)
    response.headers['Content-Type'] = 'application/json'
    return response


@vulnerability.route('/top', methods=["GET"])
def get_vul_profile():
    """
    get vulnerability top10 list
    :return:
    """
    mongo = MongoClient()
    db = mongo.ids
    vuls = db.vulnerability
    result = vuls.find().sort("date", -1).limit(10)
    result = list(result)
    for item in result:
        item['level'] = item['level'].split(' ')[0]
    result = {
        'code': 20000,
        'result': result
    }
    result = json.dumps(result, cls=MonitorJsonEncoder)
    response = make_response(result)
    response.headers['Content-Type'] = 'application/json'
    return response


@vulnerability.route('/save', methods=["POST"])
def save_scan_record():
    data = request.get_json()
    if 'record' not in data:
        return jsonify({
            'code': 50004,
            'result': 'post data error'
        })
    record = data['record']
    mongo = MongoClient()
    db = mongo.ids
    record_collect = db.record
    r = list(record_collect.find({'ip': record['ip']}))
    if len(r) == 0:
        record_collect.insert(record)
        result = 'success'
    else:
        result = 'duplicate'
    print(result)
    return jsonify({
        'code': 20000,
        'result': result
    })


@vulnerability.route('/scan/all', methods=["GET"])
def get_all_scan_record():
    mongo = MongoClient()
    db = mongo.ids
    record_collect = db.record
    result = {
        'code': 20000,
        'result': list(record_collect.find())
    }
    result = json.dumps(result, cls=MonitorJsonEncoder)
    response = make_response(result)
    response.headers['Content-Type'] = 'application/json'
    return response


@vulnerability.route('/delete', methods=["POST"])
def delete_record():
    data = request.get_json()
    if 'ip' not in data:
        return jsonify({
            'code': 50004,
            'result': 'post ip error'
        })
    ip = data['ip']
    mongo = MongoClient()
    db = mongo.ids
    record_collect = db.record
    record_collect.remove({"ip": ip})
    return jsonify({
        'code': 20000,
        'result': 'success'
    })
