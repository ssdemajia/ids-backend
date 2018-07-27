# coding=utf-8
import optparse     # 用来增加选项的支持
import multiprocessing
import threading
import os

import pcapy
from protocols.cotp import *
from protocols.s7comm import S7Header, S7_PDU_TYPE
from protocols.http import HTTPRequest, HTTP, HTTPResponse
from scapy.layers.inet import IP, Ether, TCP, UDP


from core.common import check_sudo
from core.parallel import worker
from core.setting import read_config
from core.setting import config
from core.setting import CONFIG_FILE
from core.setting import VERSION
from core.setting import SNAP_LEN
from core.setting import CAPTURE_TIMEOUT
from core.database import DbOperator


queue = multiprocessing.Queue()


def process_packet(db, content, data_link, sec, usec):
    if data_link == pcapy.DLT_RAW:      # raw ip
        pass
    elif data_link == pcapy.DLT_LINUX_SLL:   # 接口设置为any时出现
        print(1)
        print(content)
    elif data_link == pcapy.DLT_EN10MB:   # ether
        packet = Ether()
        packet.dissect(content)
        # packet.show()
        db_content = dict(tcp=["", ""], ip=["", ""], proto="", time="", func_code="")     # 需要存到数据库里的数据对象
        date = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(sec))  # 获得时间
        db_content["time"] = date
        if packet.haslayer(IP):
            db_content["ip"] = [packet[IP].src, packet[IP].dst]
            db_content["proto"] = "IP"

            if packet.haslayer(TCP):
                db_content["tcp"] = [packet[TCP].sport, packet[TCP].dport]
                db_content["proto"] = "TCP"
            elif packet.haslayer(UDP):
                db_content["tcp"] = [packet[UDP].sport, packet[UDP].dport]
                db_content["proto"] = "UDP"
                return
            if packet.haslayer(S7Header):
                db_content["proto"] = "S7COMM"
                db_content["func_code"] = S7_PDU_TYPE[packet[S7Header].ROSCTR]
            elif packet.haslayer(HTTP):
                db_content["proto"] = "HTTP"
                if packet.haslayer(HTTPRequest):
                    db_content['func_code'] = "{0} {1}".format(packet[HTTPRequest].Method,
                                                                   # packet[HTTPRequest].Path,
                                                                   getattr(packet[HTTPRequest], "Http-Version", " "))
                elif packet.haslayer(HTTPResponse):
                    db_content['func_code'] = getattr(packet[HTTPResponse], "Status-Line", " ")
            else:
                db_content['func_code'] = " "
            print(dir(packet))
            print(packet[TCP].payload)
            # print(db_content)
            # db.insert_packet(db_content)


def init_multiprocessing():
    global queue    # 使用队列，worker进程从队列中取出数据包，调用process_packet
    # for i in xrange(config.PROCESS_COUNT - 1):
    for i in xrange(1):
        process = multiprocessing.Process(target=worker, name=str(i), args=(queue, process_packet))
        # process.daemon = True
        process.start()


def init():
    """
    执行初始化操作，建立pcap_t
    :return:
    """
    config.caps = list()
    if config.pcap_file:
        config.caps.append(pcapy.open_offline(config.pcap_file))
    else:
        interfaces = set(i.strip() for i in config.MONITOR_INTERFACE.split(","))
        # MONITOR_INTERFACE是在config文件中定义的，使用逗号分隔开的端口名称，这样可以同时监控多个网卡
        devices = pcapy.findalldevs()
        print(devices)
        for interface in interfaces:
            if interface not in devices:    # 检查定义的interface是不是能够在当前电脑中找到
                exit("interface:%s not found!\n" % interface)
            config.caps.append(pcapy.open_live(interface, SNAP_LEN, True, CAPTURE_TIMEOUT))
    init_multiprocessing()


def monitor():
    def packet_handler(datalink, header, packet):
        global queue

        sec, usec = header.getts()
        d = struct.pack("=III", datalink, sec, usec)
        queue.put(d+packet)

    def _(_cap):
        datalink = _cap.datalink()  # 获得链路层类型
        print("dataLink:%d" % datalink)
        while True:
            try:
                (header, packet) = _cap.next()
                if header is not None:
                    packet_handler(datalink, header, packet)
                else:
                    continue
            except (pcapy.PcapError, socket.timeout) as e:
                print(e)
                break
            except KeyboardInterrupt:
                break
    for cap in config.caps:
        threading.Thread(target=_, args=(cap,)).start()

    try:
        while multiprocessing.active_children():
                time.sleep(0.01)
    except KeyboardInterrupt:
        print("[!]Ctrl-C pressed")


def main():
    if not check_sudo():
        exit("must sudo to get privileges")
    parser = optparse.OptionParser(version=VERSION)
    parser.add_option("-c", dest="config_file", default=CONFIG_FILE,
                      help="configuration file (default: '%s')" % os.path.split(CONFIG_FILE)[-1])
    parser.add_option("-i", dest="pcap_file", help="open pcap file for offline analysis")
    options, _ = parser.parse_args()

    read_config(options.config_file)
    for option in dir(options):  # 将option读入config中
        if isinstance(getattr(options, option), (basestring, bool)) and not option.startswith('_'):
            config[option] = getattr(options, option)
    print(config)
    init()
    monitor()


if __name__ == '__main__':
    main()
    os._exit(0)