from core import sql
from pymongo import MongoClient
import requests
import json


def get_city_by_location(lon, lat):
    url = 'http://api.map.baidu.com/geocoder/v2/?callback=renderReverse&' \
          'location={},{}&output=json&ak=GZeUqGc4Afe6zj33pGiGFrcKRmjx6kUG'
    url = url.format(lat, lon)
    result = requests.get(url)
    content = result.content.decode('utf-8')
    content = content[content.index('{'):content.rindex('}')+1]
    render_result = json.loads(content)
    if render_result['status'] != 0:
        return None
    address = render_result['result']['formatted_address']
    return address


def get_loc(ip):
    """
    use ip to get lat and lon
    :param ip:
    :return:
    """
    url = 'http://ip-api.com/json/{ip}'.format(ip=ip)
    response = requests.get(url)
    if response.status_code != 200:
        return None
    data = json.loads(response.content.decode('utf-8'))
    if data['status'] != 'success':
        return None
    address = get_city_by_location(data['lon'], data['lat'])
    if address is None:
        return None
    return data['lon'], data['lat'], address


def update_loc():
    """
    更新入侵事件位置信息
    """
    mongo = MongoClient()
    db = mongo.ids
    db.drop_collection('location')
    mongo_loc = db.location
    db = sql.DataBase()
    ip_count = db.get_event_loc()
    for ip, count in ip_count:
        print(ip)
        try:
            info = get_loc(ip)
        except Exception:
            continue
        if info is None:
            continue
        values = list(info[:2])
        values.append(count)
        mongo_loc.insert({
            'name': info[2],
            'value': values
        })


if __name__ == '__main__':
    print(get_loc("77.44.82.196"))
    # update_loc()