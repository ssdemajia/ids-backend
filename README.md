# 第一次使用
在根目录下创建ics.ini填入下面配置信息
```
[DEFAULT]
mongo = 192.168.1.107
zmapd = 127.0.0.1:8000
elasticsearch = 192.168.1.101:9200
```

### 启动Mongodb
在服务器192.168.1.107上
```
systemctl start mongod
```
填入密码501501501

mongodb databases
```
ids
shodan
```
ids-collections
```
record: 漏洞扫描储存的结果
location：入侵事件ip和经纬信息
vulnerability：漏洞库
scanRecord: 保存每天的漏洞扫描记录,包括高危漏洞多少个，中危漏洞多少，低危漏洞多少
```
shodan-collections
```
bacnet
ethip
modbus
omron
s7
all
distribute
```

