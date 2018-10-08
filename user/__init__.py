from flask import Blueprint, request, jsonify

import sys
import json

admin = Blueprint('user', __name__)


@admin.route('/login', methods=["POST"])
def login():
    req_content = json.loads(request.data.decode("utf-8"))
    admin = req_content["username"]
    password = req_content["password"]
    print("admin:{} password:{}".format(admin, password), file=sys.stderr)
    return jsonify({"code": 20000, 'token': "shaoshuai"})


@admin.route('/logout', methods=["POST"])
def logout():
    req = request.get_json()
    return jsonify({"code": 20000})


@admin.route('/info', methods=["GET"])
def get_info():
    token = request.args.get("token")
    return jsonify({
        "code": 20000,
        'roles': 'admin',
        'name': 'shaoshuai',
        'avatar': '123'
    })
