import requests
import re
import xlwt
import time
from bs4 import BeautifulSoup
import random
from pymongo import MongoClient
headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Encoding': 'gzip, deflate, sdch',
        'Accept-Language': 'zh-CN,zh;q=0.8',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36'
}
cookies = {'__jsluid': '01625427b147ef66aa4abe848e4d0008'}
mongo = MongoClient()
db = mongo.ids
vul = db.vulnerability


def get_urls():
    url = "http://ics.cnvd.org.cn/?title=&max=10000&offset=10"
    r = requests.get(url, headers=headers, cookies=cookies)
    html = r.text
    soup = BeautifulSoup(html, 'lxml')
    hrefs = []
    for tag in soup.find('tbody', id='tr').find_all('a', href=re.compile('http://www.cnvd.org.cn/flaw/show')):
        hrefs.append(tag.attrs['href'])
    print("Number of url is: %d" % len(hrefs))
    return hrefs

i = 0
def get_content(url):
    global i
    print("%i [URL]%s" % (i, url))
    # time.sleep(random.random())
    r = requests.get(url, headers=headers, cookies=cookies)
    html = r.text
    soup = BeautifulSoup(html, 'lxml')
    tbody = soup.find('tbody')
    if not tbody:
        print("this url didn't has table, [URL]%s" % url)
        time.sleep(random.random())
        get_content(url)
        return
    trs = tbody.find_all('tr')
    if not trs:
        print("this url didn't has trs")
        return
    i += 1
    item = dict()
    item['title'] = soup.find("h1").text.strip()
    print(item['title'])
    item['cnvd'] = trs[0].find_all('td')[1].text.strip()
    item['date'] = trs[1].find_all('td')[1].text.strip()
    item['level'] = trs[2].find_all('td')[1].text.strip()
    item['product'] = trs[3].find_all('td')[1].text.strip()
    item['cve'] = trs[4].find_all('td')[1].text.strip()
    item['description'] = trs[5].find_all('td')[1].text.strip()
    item['link'] = trs[6].find_all('td')[1].text.strip()
    item['solve'] = trs[7].find_all('td')[1].text.strip()
    item['patch'] = trs[8].find_all('td')[1].text.strip()
    item['verification'] = trs[9].find_all('td')[1].text.strip()
    item['submit_date'] = trs[10].find_all('td')[1].text.strip()
    item['update_date'] = trs[11].find_all('td')[1].text.strip()
    item['attachment'] = trs[12].find_all('td')[1].text.strip()
    vul.insert(item)
    # return item


if __name__ == '__main__':
    # db.drop_collection('vulnerability')
    # urls = get_urls()
    # for url in urls:
    #     get_content(url)
    url = 'http://www.cnvd.org.cn/flaw/show/CNVD-2017-14601'
    # item = get_content(url)
    # print(item)
