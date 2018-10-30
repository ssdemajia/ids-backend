from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException

from scan_models.s7 import s7_scan, s7_resolve
from scan_models.modbus import modbus_scan, modbus_resolve
from scan_models.bacnet import bacnet_scan, bacnet_resolve
from scan_models.omron import omron_scan, omron_resolve
from scan_models.ethip import ethip_scan, ethip_resolve
from scan_models.poconos import proconos_scan, proconos_resolve
from scan_models.pcworx import pcworx_scan, pcworx_resolve

import os
import itertools
import requests
# EthNet/IP  TCP 44818
# Mitsubishi MELSOFT UDP/5008 TCP/5007
# omron-udp omron fins 9600
# iec104   2404
# s7 TCP 102
# Schneider modbus/tcp TCP 502
# dnp3 20000
# bacnet udp 47808
# proconos 20547
# wincc udp 137
# scalance udp 161
tcp_ports = [44818, 102, 502, 1962, 20547, 5007]
udp_ports = [161, 137, 9600, 47808, 5008]
company = ['siemens', 'schneider', 'mitsubishi', 'rockwell', 'pcworx', 'proconos']
protocols = ['bacnet']
special_type = ['plc']


def check_clearscada(ip_address):
    try:
        resp = requests.get('http://'+ip_address)
    except Exception as e:
        return ""
    info = resp.headers.get('Server', '')
    if 'clearscada' in info.lower():
        return info
    return ""


def test_service(ip_address):
    tcp_options = [("-sT -p " + str(_port), _port) for _port in tcp_ports]
    udp_options = [("-sU -p " + str(_port), _port) for _port in udp_ports]
    useful_port = []
    for option, port in itertools.chain(tcp_options, udp_options):
        print(port)
        if test_port(ip_address, option):
            useful_port.append(port)
    print(useful_port)
    return useful_port


def test_port(ip_address, option):
    nm = NmapProcess(ip_address, options=option)
    nm.run()
    if nm.rc != 0:
        return False
    parsed = NmapParser.parse(nm.stdout)
    if len(parsed.hosts) == 0:
        return False
    host = parsed.hosts[0]
    if len(host.services) == 0:
        return False
    service = host.services[0]
    if "open" in service.state:
        return True
    return False


def choice_protocol(ip_address, ports, nse_path):
    if len(ports) == 0:
        return
    for port in ports:
        need_udp = ""
        script_path = nse_path
        if port == 102:  # s7comm
            script_path += '/s7-enumerate.nse'
        elif port == 502:  # modbus/tcp
            script_path += '/modicon-info.nse'
        elif port == 47808:  # bacnet
            script_path += '/BACnet-discover-enumerate.nse'
            need_udp = '-sU'
        elif port == 9600:  # omron-udp
            script_path += '/omronudp-info.nse'
            need_udp = '-sU'
        elif port == 44818:  # ethip
            script_path += '/enip-enumerate.nse'
        elif port == 20547:  # proconos
            script_path += '/proconos-info.nse'
        elif port == 1962:  # pcworx
            script_path += '/pcworx-info.nse'
        elif port == 5007:  #
            script_path += '/melsoft-tcp.nse'
        elif port == 5008:  #
            script_path += '/melsoft-udp.nse'
            need_udp = '-sU'
        elif port == 161:   # siemens scalance
            script_path += '/SCADA/Siemens-Scalance-module.nse'
            need_udp = '-sU'
        elif port == 137:
            script_path += '/SCADA/Siemens-WINCC.nse'
            need_udp = '-sU'
        elif port == 80:
            web_path = [
                '/SCADA/Siemens-HMI-miniweb.nse',   # todo
                '/SCADA/Siemens-CommunicationsProcessor.nse'    # todo
            ]
        else:
            raise TypeError('Unsupport Port')
        option = '{need_udp} -p {port} --script {script}'.format(need_udp=need_udp, port=port, script=script_path)
        info = get_info(ip_address, option, port)
        if info is not None and len(info) > 0:
            return info
    return None


def get_info(ip_address, option, port):
    nm = NmapProcess(ip_address, options=option)
    nm.run()

    if nm.rc != 0:
        print(nm.stderr)
    try:
        parsed = NmapParser.parse(nm.stdout)
    except NmapParserException:
        return
    print(parsed)
    if len(parsed.hosts) == 0:
        return
    host = parsed.hosts[0]
    if len(host.services) == 0:
        return
    service = host.services[0]
    if len(service._service_extras) == 0:
        return
    script_output = service._service_extras['scripts']
    if len(script_output) == 0:
        return
    protocol_element = script_output[0]['elements']
    if protocol_element is None:
        return
    info = parse_protocol_info(port, protocol_element)

    return info


def parse_protocol_info(port, protocol_element):
    info = dict()
    system_info = dict()
    if port == 102:     # s7
        info = s7_resolve(protocol_element)
    elif port == 502:   # modbus
        info = modbus_resolve(protocol_element)
    elif port == 47808:  # bacnet
        info = bacnet_resolve(protocol_element)
    elif port == 9600:  # omron
        info = omron_resolve(protocol_element)
    elif port == 44818:     # ethip
        info = ethip_resolve(protocol_element)
    elif port == 20547:     # proconos
        info = proconos_resolve(protocol_element)
    elif port == 1962:
        info = pcworx_resolve(protocol_element)
    # elif port == 5007 or port == 5008:
    #     info['CPU型号'] = protocol_element.get('CPUINFO', '')
    #     info['PLC类型'] = 'Mitsubishi MelSoft'
    #     info['profile'] = 'Mitsubishi MelSoft'
    #     info['key'] = ['Mitsubishi MelSoft']
    if len(info) != 0:
        system_info['info'] = info
        system_info['port'] = port
    return system_info


def get_system_info(ip, nse_path):
    ports = test_service(ip)
    ifs = choice_protocol(ip, ports, nse_path)
    return ifs


def vul_scan(keys, port):
    if port == 102:     # s7
        info = s7_scan(keys)
    elif port == 502:   # modbus
        info = modbus_scan(keys)
    elif port == 47808:  # bacnet
        info = bacnet_scan(keys)
    elif port == 9600:  # omron
        info = omron_scan(keys)
    elif port == 44818:     # ethip
        info = ethip_scan(keys)
    elif port == 20547:     # proconos
        info = proconos_scan(keys)
    elif port == 1962:   # pcworx
        info = pcworx_scan(keys)
    elif port == 5007 or port == 5008:  # todo
        pass

    return info


if __name__ == '__main__':
    # ip = '140.206.150.51'  # s7 o
    # ip = "166.139.80.97"  # modbus o
    # ip = "24.248.68.156"  # bacnet o
    ip = "166.250.228.16"  # enip
    # ip = "37.82.140.153"  # pcworx
    # ip = "193.252.187.123"  # omronudp
    # ip = "188.94.194.99"  # proconos o
    # ip = "88.26.221.244"  # melsoft tcp o
    # ip = '200.29.11.5' # 789 red lion G303
    # ip = '166.149.137.48'  # mitsubishi MELSOFT UDP/5008 TCP/5007

    nse_path = os.path.join(os.getcwd(), '..', 'nse')
    result = get_system_info(ip, nse_path)

    # import json
    # import sys
    # print(json.dump(result, sys.stdout))

    r = vul_scan(result['key'])
    # r = vul_scan(['CPU 314'])
    for i in r:
        print(i['title'])

    # print(check_clearscada('98.23.98.22'))