# coding=utf-8
from __future__ import print_function

from flask import Flask
from flask import request
from flask import jsonify
from flask import make_response
from flask_cors import CORS
from werkzeug.utils import secure_filename
from pymongo import MongoClient

from core.sql import long2ip
from core.read_pcap import PcapReader
from core.monitor import Monitor, MonitorJsonEncoder

from user import admin
from vul import vulnerability

import sys
import core.sql as sql
import os
import pcapy
import pymysql
import json

# from core.model import db

app = Flask(__name__)
# db.init_app(app)
CORS(app, supports_credentials=True)
UPLOAD_FOLDER = "upload"
ALLOWED_EXTENSIONS = {"pcap", "cap"}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['JSON_AS_ASCII'] = False

app.register_blueprint(admin, url_prefix='/user')
app.register_blueprint(vulnerability, url_prefix='/vul')


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


def allow_file(filename):
    return "." in filename and filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


@app.route("/upload", methods=["POST"])
def upload():
    if request.method == "POST":
        file = request.files['file']
        if file and allow_file(file.filename):
            filename = secure_filename(file.filename)
            path = os.path.join(os.getcwd(), app.config['UPLOAD_FOLDER'], filename)
            file.save(path)
            read = PcapReader(path)
            result = read.get_specify()
            read.close()
            return jsonify({
                'code': 20000,
                'result': result
            })
    response = jsonify({
        'error': 'Error method',
        'code': 50024})
    return response


@app.route("/upload/list", methods=["GET"])
def upload_lists():
    lists = os.listdir(os.path.join(os.getcwd(), app.config['UPLOAD_FOLDER']))
    return jsonify({
        'code': 20000,
        'lists': lists
    })


@app.route("/upload/<filename>", methods=["GET"])
def get_file_length(filename):
    path = os.path.join(os.getcwd(), app.config['UPLOAD_FOLDER'], filename)
    read = PcapReader(path, keep_packets=True, summary=True)
    length = read.packet_length()
    read.close()
    return jsonify({
        'code': 20000,
        'length': length
    })


@app.route("/upload/<filename>", methods=["POST"])
def get_dissect_file(filename):
    data = request.get_json()
    start = data['start']
    end = data['end']
    path = os.path.join(os.getcwd(), app.config['UPLOAD_FOLDER'], filename)
    read = PcapReader(path, keep_packets=True, summary=True)
    result, length = read.get_specify(start, end)
    read.close()
    return jsonify({
        'code': 20000,
        'result': result,
        'length': length
    })


@app.route("/upload/packet", methods=["POST"])
def get_packet_detail():
    data = request.get_json()
    id = int(data['id'])
    filename = data['filename']
    file_list = os.listdir(os.path.join(os.getcwd(), app.config['UPLOAD_FOLDER']))
    if filename not in file_list:
        return jsonify({
            'code': 500010,
            'error': 'Error filename'
        })
    file_path = os.path.join(os.getcwd(), app.config['UPLOAD_FOLDER'], filename)
    reader = PcapReader(file_path, summary=False, keep_packets=True)
    info = reader.get_detail(id)
    reader.close()
    return jsonify({
        'code': 20000,
        'result': info
    })


@app.route("/upload/<filename>", methods=["DELETE"])
def remove_pcap(filename):
    path = os.path.join(os.getcwd(), app.config['UPLOAD_FOLDER'], filename)
    os.remove(path)
    return jsonify({
        'code': 20000,
        'result': 'success'
    })


"""
use to monitor
"""


@app.route("/monitor/interface")
def get_interface_list():
    devs = pcapy.findalldevs()
    devs = [{"label": v, "value": v} for v in devs]
    return jsonify({
        'code': 20000,
        'result': devs
    })


@app.route("/monitor/start", methods=["POST"])
def start_monitor():
    data = request.get_json()
    count = data['count']
    interface = data['inter']
    monitor = Monitor(interface, int(count))
    monitor.start()
    return jsonify({
        'code': 20000,
    })


@app.route("/monitor/packet", methods=["POST"])
def send_packet():
    data = request.get_json()
    start = data['start']
    end = data['end']

    mongo = MongoClient()
    db = mongo.ids
    packet = db.packet
    cursor = packet.find({"id": {"$gte": start, "$lt": end}})
    result = list(cursor)
    cursor = packet.find().count()
    result = {
        'code': 20000,
        'result': result,
        'count': cursor
    }
    result = json.dumps(result, cls=MonitorJsonEncoder)
    response = make_response(result)
    response.headers['Content-Type'] = 'application/json'
    return response


"""
use to dashboard
"""


@app.route("/dashboard/sig/<int:sig_priority>", methods=["GET"])
def get_sig_count(sig_priority):
    try:
        db = sql.DataBase()
    except pymysql.err.OperationalError as e:
        return jsonify({
            'code': 50027,
            'error': 'db error'
        })
    count = db.get_event_count_by_sig(sig_priority)
    return jsonify({
        'code': 20000,
        'sig': sig_priority,
        'count': count
    })


@app.route('/dashboard/sig/<time>/<int:sig_priority>', methods=["GET"])
def get_sig_count_by_time(time, sig_priority):
    db = sql.DataBase()
    counts = db.get_event_count_by_time_sig(time, sig_priority)
    return jsonify({
        'code': 20000,
        'sig': sig_priority,
        'time': time,
        'counts': counts
    })


@app.route('/dashboard/sig/top/<int:num>', methods=["GET"])
def get_event_count_by_num(num):
    db = sql.DataBase()
    counts = db.get_event_count_top(num)
    return jsonify({
        'code': 20000,
        'counts': counts
    })


if __name__ == '__main__':
    app.run(debug=True, port=9001)
