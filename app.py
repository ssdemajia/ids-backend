# coding=utf-8
from __future__ import print_function
import json

from flask import Flask
from flask import request
from flask import jsonify
from flask_cors import CORS
import sys
import sql
from sql import long2ip
import time

app = Flask(__name__)
CORS(app, supports_credentials=True)


@app.route('/user/login', methods=["POST"])
def login():
    req_content = json.loads(request.data.decode("utf-8"))
    admin = req_content["username"]
    password = req_content["password"]
    print("admin:{} password:{}".format(admin, password), file=sys.stderr)
    return jsonify({"code": 20000, 'token': "shaoshuai"})


@app.route('/user/info', methods=["GET"])
def get_info():
    token = request.args.get("token")
    return jsonify({
        "code": 20000,
        'roles': 'admin',
        'name': 'shaoshuai',
        'avatar': '123'
    })


@app.route('/events', methods=["POST"])
def get_events():
    db = sql.DataBase()
    cid = json.loads(request.data.decode('utf-8'))['cid']
    print(cid, file=sys.stderr)
    event_count = db.get_event_count()
    print(event_count, file=sys.stderr)
    if event_count <= cid:
        response = jsonify({
            'error': 'id too large',
            'code': 50016})
        response.status_code = 404
        return response
    events = db.get_events(cid)
    print(events, file=sys.stderr)
    return jsonify({
        'code': 20000,
        'result': events
    })


@app.route('/count/<type>', methods=["GET"])
def get_event_count(type):
    print(type, file=sys.stderr)
    db = sql.DataBase()
    try:
        count = db.get_event_count(type)
    except Exception:
        response = jsonify({
            'error': 'type error',
            'code': 50024
        })
        response.status_code = 404
        return response
    return jsonify({
        'code': 20000,
        'count': count
    })


@app.route('/detail', methods=["POST"])
def get_event_detail():
    db = sql.DataBase()
    data = request.get_json()
    cid = data['cid']
    print("[get_event_detail]  {}".format(cid), file=sys.stderr)
    protocol = db.get_event_protocol(cid)
    if protocol is None:
        response = jsonify({
            'error': 'Unknown protocol',
            'code': 50020})
        response.status_code = 404
        return response
    protocol = protocol[0]  # 数据库查询到结果就是一个元组表示
    protocol = sql.protocol_map[protocol]
    if protocol in ["TCP", "UDP", "IP", "ICMP"]:
        ip_detail, proto4_detail = db.get_event_detail(cid, protocol)
        ip_detail = list(ip_detail)
        ip_detail[0] = long2ip(ip_detail[0])
        ip_detail[1] = long2ip(ip_detail[1])
        proto4_detail = list(proto4_detail)
    else:
        response = jsonify({
            'error': 'Unknown protocol',
            'code': 50020})
        response.status_code = 404
        return response
    event = db.get_event(cid)
    return jsonify({
        'code': 20000,
        'ip': ip_detail,
        'proto4': proto4_detail,
        'protocol': protocol,
        'event': event
    })


@app.route("/v2/events", methods=["POST"])
def get_events_v2():
    db = sql.DataBase()
    data = request.get_json()
    start = data['start']
    end = data['end']
    check_tcp = data['checkTCP']
    check_udp = data['checkUDP']
    check_ip = data['checkIP']
    check_icmp = data['checkICMP']
    events = db.get_events_v2(start, end, check_tcp, check_udp, check_ip, check_icmp)
    return jsonify({
        'code': 20000,
        'result': events
    })


if __name__ == '__main__':
    app.run()
