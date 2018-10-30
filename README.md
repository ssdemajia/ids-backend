mongodb默认的数据目录为/data/db

open mongod
```bash
sudo mongod --logpath=/var/log/mongodb/log --fork
```
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
```