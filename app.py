# coding=utf-8
from __future__ import print_function
import json
from flask import Flask
from flask import request
from flask import jsonify
from flask import make_response
from flask_cors import CORS
from werkzeug.utils import secure_filename
import sys
import core.sql as sql
from core.sql import long2ip
from core.read_pcap import PcapReader
import os
from core.monitor import Monitor, MonitorJsonEncoder
from core.vul_scan import get_result
import pcapy
from pymongo import MongoClient
# from core.model import db

app = Flask(__name__)
# db.init_app(app)
CORS(app, supports_credentials=True)
UPLOAD_FOLDER = "upload"
ALLOWED_EXTENSIONS = {"pcap", "cap"}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['JSON_AS_ASCII'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://snort:shaoshuai@192.168.178.11/snort'
nse_path = os.path.join(os.getcwd(), 'nse')

@app.route('/user/login', methods=["POST"])
def login():
    req_content = json.loads(request.data.decode("utf-8"))
    admin = req_content["username"]
    password = req_content["password"]
    print("admin:{} password:{}".format(admin, password), file=sys.stderr)
    return jsonify({"code": 20000, 'token': "shaoshuai"})


@app.route('/user/logout', methods=["POST"])
def logout():
    req = request.get_json()
    return jsonify({"code": 20000})


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
            return jsonify(result)
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
def get_dissect_file(filename):
    path = os.path.join(os.getcwd(), app.config['UPLOAD_FOLDER'], filename)
    read = PcapReader(path)
    result = read.get_specify()
    read.close()
    return jsonify({
        'code': 20000,
        'result': result
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
    db = sql.DataBase()
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


@app.route('/dashboard/vul/top', methods=["GET"])
def get_vul_profile():
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


# vulnerability
@app.route('/vul/scanner', methods=["POST"])
def get_system_info():
    ip = request.get_json()['ip']
    info = get_result(ip, nse_path)
    return jsonify({
        'code': 20000,
        'result': info
    })


@app.route('/vul/list', methods=['POST'])
def get_vulnerability():
    data = request.get_json()
    start = int(data['start'])
    end = int(data['end'])
    mongo = MongoClient()
    db = mongo.ids
    vulner = db.vulnerability
    cursor = vulner.find().limit(end-start).skip(start)
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

if __name__ == '__main__':
    app.run(debug=True, port=9001)
