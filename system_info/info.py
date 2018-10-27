from flask import Blueprint, request, jsonify, make_response

import psutil

system_info = Blueprint('sysinfo', __name__)


@system_info.route('/summary')
def get_summary():
    cpu_percent = psutil.cpu_percent()
    mem_percent = psutil.virtual_memory().percent
    return jsonify({
        'code': 20000,
        'cpu': cpu_percent,
        'mem': mem_percent
    })


