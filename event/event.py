from flask import Blueprint, request, jsonify, make_response
from pymongo import MongoClient
from core.utils import get_loc
from core import sql
import pymysql



events = Blueprint('events', __name__)

"""
use to dashboard
"""


@events.route("/sig/<int:sig_priority>", methods=["GET"])
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


@events.route('/sig/<time>/<int:sig_priority>', methods=["GET"])
def get_sig_count_by_time(time, sig_priority):
    db = sql.DataBase()
    counts = db.get_event_count_by_time_sig(time, sig_priority)
    return jsonify({
        'code': 20000,
        'sig': sig_priority,
        'time': time,
        'counts': counts
    })


@events.route('/sig/<time>', methods=["GET"])
def get_all_count_by_time(time):
    db = sql.DataBase()
    count1 = db.get_event_count_by_time_sig(time, 1)
    count2 = db.get_event_count_by_time_sig(time, 2)
    count3 = db.get_event_count_by_time_sig(time, 3)
    result = [[] for i in range(4)]
    for i in range(len(count1)):
        result[0].append(count1[i][0])
        result[1].append(count2[i][0])
        result[2].append(count3[i][0])
        print(count3[i][1:])
        result[3].append(".".join(str(d) for d in count3[i][1:]))
    return jsonify({
        'code': 20000,
        'time': time,
        'counts': result
    })


@events.route('/sig/top/<int:num>', methods=["GET"])
def get_event_count_by_num(num):
    db = sql.DataBase()
    counts = db.get_event_count_top(num)
    return jsonify({
        'code': 20000,
        'counts': counts
    })


@events.route('/loc', methods=["GET"])
def get_event_location():
    mongo = MongoClient()
    db = mongo.ids
    mongo_loc = db.location
    cursor = mongo_loc.find().limit(100)
    result = list(cursor)
    result = [{'name': item['name'], 'value': item['value']} for item in result]
    return jsonify({
        'code': 20000,
        'location': result
    })


@events.route('/score', methods=['GET'])
def get_system_score():
    db = sql.DataBase()
    score = db.get_score()
    return jsonify({
        'code': 20000,
        'score': score
    })
