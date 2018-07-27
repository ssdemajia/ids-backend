# coding=utf-8
from __future__ import print_function
import pymysql
import socket
import sys
import time
HOST = "192.168.178.11"
DATABASE = "snort"
USER = "snort"
PASSWORD = "shaoshuai"

protocol_map = {
    socket.IPPROTO_IP: "IP",
    socket.IPPROTO_ICMP: "ICMP",
    socket.IPPROTO_TCP: "TCP",
    socket.IPPROTO_UDP: "UDP"
}


class DBError(Exception):
    # an error about operate not allow
    def __init__(self, what):
        self._what = what


class DataBase:
    def __init__(self):
        self.__conn = pymysql.connect(host=HOST,
                                      user=USER,
                                      passwd=PASSWORD,
                                      db=DATABASE,
                                    )

    def __del__(self):
        self.__conn.close()

    def get_event_count(self, type=None):
        if type == 'event':
            table = "event"
        elif type == 'icmp':
            table = 'icmphdr'
        elif type == 'udp':
            table = 'udphdr'
        elif type == 'tcp':
            table = 'tcphdr'
        elif type == 'ip':
            table = 'iphdr'
        else:
            raise DBError("unkown type-.-")

        # query = "select count(cid) from '%s';" % table
        query = "select count(cid) from %s" % table
        # print(query % table)
        cur = self.__conn.cursor()
        cur.execute(query)
        result = cur.fetchone()
        cur.close()
        return result[0]

    def create_ids_table(self):
        sql = "DROP TABLE IF EXISTS ids_event"
        cur = self.__conn.cursor()
        cur.execute(sql)
        sql = """CREATE TABLE ids_event (
            sid  INT UNSIGNED NOT NULL,
            cid INT UNSIGNED NOT NULL,
            signature INT UNSIGNED NOT NULL ,
            sig_name VARCHAR(255),
            sig_class_id INT UNSIGNED,
            sig_priority INT UNSIGNED,
            timestamp DATETIME NOT NULL,
            ip_src INT UNSIGNED,
            ip_dst INT UNSIGNED,
            ip_proto INT,
            layer4_sport INT UNSIGNED,
            layer4_dport INT UNSIGNED,
            PRIMARY KEY(sid, cid),
            INDEX(signature),
            INDEX(sig_name),
            INDEX(sig_class_id),
            INDEX(sig_priority),
            INDEX(timestamp),
            INDEX(ip_src),
            INDEX(ip_dst),
            INDEX(ip_proto),
            INDEX(layer4_sport),
            INDEX(layer4_dport) );"""
        cur.execute(sql)
        # sql = "DROP TABLE IF EXISTS ids_cache"
        # cur.execute(sql)
        cur.close()
        print("创建数据表成功", file=sys.stderr)

    def get_event_detail(self, cid, protocol):
        ip_sql = "SELECT ip_src, " \
                 "ip_dst, " \
                 "ip_ver, " \
                 "ip_hlen, " \
                 "ip_tos, " \
                 "ip_len, " \
                 "ip_id, " \
                 "ip_flags, " \
                 "ip_off ," \
                 "ip_ttl, " \
                 "ip_csum " \
              "FROM iphdr " \
              "WHERE iphdr.cid = %s;" % cid
        if protocol == "TCP":
            proto4_sql = \
                "SELECT tcp_sport, " \
                "tcp_dport, " \
                "tcp_seq, " \
                "tcp_ack, " \
                "tcp_off, " \
                "tcp_res, " \
                "tcp_flags, " \
                "tcp_win, " \
                "tcp_csum, " \
                "tcp_urp " \
                "FROM tcphdr " \
                "WHERE tcphdr.cid = %s;" % cid
        elif protocol == "UDP":
            proto4_sql = "SELECT udp_sport, " \
                         "udp_dport, " \
                         "udp_len, " \
                         "udp_csum " \
                         "FROM snort.udphdr " \
                         "WHERE udphdr.cid = %s;" % cid
        elif protocol == "ICMP":
            proto4_sql = "SELECT icmp_type, " \
                         "icmp_code, " \
                         "icmp_csum, " \
                         "icmp_id, " \
                         "icmp_seq " \
                         "FROM icmphdr " \
                         "WHERE icmphdr.cid = %s;" % cid
        cur = self.__conn.cursor()
        cur.execute(ip_sql)
        ip_detial = cur.fetchone()
        cur.execute(proto4_sql)
        proto4_detail = cur.fetchone()
        return ip_detial, proto4_detail

    def get_events_v2(self, start, end, check_tcp, check_udp, check_ip, check_icmp):
        """
        根据选项选择指定协议的事件，同时是指定长度内的事件给客户端
        :param start:
        :param end:
        :param check_tcp:
        :param check_udp:
        :param check_ip:
        :param check_icmp:
        :return:
        """
        exp = []
        if check_tcp:
            exp.append(" iphdr.ip_proto = 6 ")
        if check_udp:
            exp.append(" iphdr.ip_proto = 17 ")
        if check_ip:
            exp.append(" iphdr.ip_proto = 0 ")
        if check_icmp:
            exp.append(" iphdr.ip_proto = 1 ")
        if len(exp) != 0:
            exp = "or".join(exp)
        sql = "SELECT event.sid, " \
              "event.cid, " \
              "event.signature, " \
              "sig_name, " \
              "sig_class_id, "\
              "sig_priority," \
              "timestamp," \
              "ip_src," \
              "ip_dst," \
              "ip_proto" \
              " FROM event, iphdr, signature " \
              "WHERE event.cid = iphdr.cid AND" \
              " event.signature = signature.sig_id AND" \
              " (%s)" \
              " LIMIT %s, %s;" \
              % (exp, start, end)
        print(sql)
        cur = self.__conn.cursor()
        cur.execute(sql)
        results = cur.fetchall()
        events = []
        for result in results:
            temp = list(result)
            temp[6] = time.mktime(temp[6].timetuple())
            temp[7] = long2ip(temp[7])
            temp[8] = long2ip(temp[8])  # Todo 可以放到浏览器再转换，减少带宽使用
            temp[9] = protocol_map[temp[9]]
            events.append(list(temp))
        return events

    def get_event_protocol(self, cid):
        sql = "SELECT ip_proto FROM iphdr where iphdr.cid = %s;" % cid
        cur = self.__conn.cursor()
        cur.execute(sql)
        result = cur.fetchone()
        print(result)
        return result

    def get_event(self, cid):
        """
        获得单个事件的详细信息
        :param cid:
        :return:
        """
        sql = "SELECT event.sid, " \
              "event.cid, " \
              "event.signature, " \
              "sig_name, " \
              "sig_class_id, "\
              "sig_priority," \
              "timestamp," \
              "ip_src," \
              "ip_dst," \
              "ip_proto" \
              " FROM event, iphdr, signature " \
              "WHERE event.cid = iphdr.cid AND" \
              " event.signature = signature.sig_id AND" \
              " event.cid = %s;" % cid
        cur = self.__conn.cursor()
        cur.execute(sql)
        result = cur.fetchone()
        if result is None:
            return []
        event = list(result)
        event[6] = time.mktime(event[6].timetuple())
        event[7] = long2ip(event[7])
        event[8] = long2ip(event[8])  # Todo 可以放到浏览器再转换，减少带宽使用
        event[9] = protocol_map[event[9]]
        return event


def long2ip(long_var):
    """
    将long长整型的ip表示为字符串形式
    比如:3232281273 => 192.168.178.185
    :param long_var:
    :return:
    """
    if long_var < 0 or long_var > 4294967295:
        return ""
    ip = ""
    for i in range(3, -1, -1):
        temp = 256**i
        ip += str(int(long_var/temp))
        long_var -= int(long_var/temp)*temp
        if i != 0:
            ip += "."
    return ip


if __name__ == '__main__':
    db = DataBase()
    # print(db.get_event_count('udp'))
    # import time
    # print(time.mktime(db.get_events(2)[0][6].timetuple()))
    # db.create_ids_table()

    # print(db.get_events(1))
    print(long2ip(3232281273))
    print(db.get_events_v2(0, 10, True, True, True, True))
    print(db.get_events_v2(0, 60, True, True, True, False))
    print(db.get_events_v2(0, 600, True, True, True, False))
    print(db.get_events_v2(0, 60, False, True, True, False))
    print(db.get_event_protocol(200))