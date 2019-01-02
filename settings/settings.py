from flask import Blueprint, request, jsonify, make_response
from core import config

settings = Blueprint('settings', __name__)


@settings.route('/', methods=['GET', 'POST'])
def settings_handle():
    if request.method == 'GET':
        return jsonify({
            'data': config.dict(),
            'code': 20000
        })
    data = request.json
    settings = data['settings']
    config_dict = config.dict()
    for k, v in settings.items():
        if k in config_dict:
            config[k] = v
    config.save()
    return jsonify({'code': 20000})
