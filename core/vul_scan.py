from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException
import os
import itertools

# EthNet/IP  TCP 44818
# Mitsubishi MELSOFT UDP/5008 TCP/5007
# omron-udp omron fins 9600
# iec104   2404
# s7 TCP 102
# Schneider modbus/tcp TCP 502
# dnp3 20000
# bacnet udp 47808
tcp_ports = [44818, 102, 502, 1962, 20547, 5007]
udp_ports = [9600, 47808, 5008]


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
    if nm.rc == 0:
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
    info = []
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
        else:
            raise TypeError('Unsupport Port')
        option = '{need_udp} -p {port} --script {script}'.format(need_udp=need_udp, port=port, script=script_path)
        info.append(get_info(ip_address, option, port))
    return info


def get_info(ip_address, option, port):
    nm = NmapProcess(ip_address, options=option)
    nm.run()
    info = dict()
    if nm.rc == 0:
        # print(nm.stdout)
        parsed = NmapParser.parse(nm.stdout)
        print(parsed)
        if len(parsed.hosts) == 0:
            return info
        host = parsed.hosts[0]
        if len(host.services) == 0:
            return info
        service = host.services[0]
        if len(service._service_extras) == 0:
            return
        script_output = service._service_extras['scripts']
        if len(script_output) == 0:
            return
        protocol_element = script_output[0]['elements']

        parse_protocol_info(port, protocol_element, info)
    else:
        print(nm.stderr)
    return info


def parse_protocol_info(port, protocol_element, info):
    if port == 102:
        info['硬件信息'] = protocol_element['Basic Hardware']
        info['系统名称'] = protocol_element['System Name']
        info['信息版权'] = protocol_element['Copyright']
        info['版本号'] = protocol_element['Version']
        info['模块'] = protocol_element['Module Type']
        info['序列号'] = protocol_element['Serial Number']
        info['模块型号'] = protocol_element['Module']
    # elif port == 502:
    #     info['']


def get_result(ip, nse_path):
    ports = test_service(ip)
    info = choice_protocol(ip, ports, nse_path)
    return info


if __name__ == '__main__':
    ip = '140.206.150.51'  # s7 o
    # ip = "166.139.80.97"  # modbus o
    # ip = "108.237.140.9 "  # bacnet o
    # ip = "166.250.228.16"  # enip
    # ip = "151.59.129.100"  # pcworx
    # ip = "193.252.187.123"  # omronudp
    # ip = "166.143.173.169"  # proconos o
    # ip = "88.26.221.244"  # melsoft tcp o
    # ip = '200.29.11.5' # 789 red lion G303
    nse_path = os.path.join(os.getcwd(), '..', 'nse')
    result = get_result(ip, nse_path)
    import json
    import sys
    print(json.dump(result, sys.stdout))
    # print(os.listdir(os.path.join(os.getcwd(), '..', 'nse')))
    # for port in useful_ports:
    #     info = get_system_info(ip, port, path)
    #     print(info)





