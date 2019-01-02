from flask import Blueprint, request, jsonify, make_response
from core import config

import requests

console = Blueprint('console', __name__)


@console.route('/jobs', methods=['GET', 'POST', 'DELETE'])
def jobs():
    url = 'http://' + config['zmapd'] + '/api/jobs/'
    if request.method == 'GET':
        resp = requests.get(url)
        return jsonify({
            'code': 20000,
            'jobs': resp.json()
        })
    elif request.method == 'POST':
        job = request.json['job']
        resp = requests.post(url, data=job)
        if resp.status_code == 201:
            return jsonify({
                'code': 20000
            })
    elif request.method == 'DELETE':
        id = request.json['id']
        resp = requests.delete(url+id+'/')
        if resp.status_code == 204:
            return jsonify({
                'code': 20000
            })
    return jsonify({
        'code': 20000,
        'error': resp.status_code
    })
