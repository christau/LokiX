#!/usr/bin/env python3
# This is an linux/unix agent for the Lokix webapp
import socket
import threading
import requests
import json
import sys
import os
from os.path import exists
import subprocess
import time

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if len(sys.argv)<2:
    raise Exception("No server host specified")

lokix_server=sys.argv[1]


def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP
def post_data(url, data):
    r = requests.post('https://'+lokix_server+url, data=json.dumps(data), headers={'Content-type': 'application/json', 'Accept': 'application/json'}, verify=False)
    return r.json()

class HeartbeatTask(threading.Thread):
    def run(self,*args,**kwargs):
        try:
            while True:
                post_data('/be/api/heartbeat',{'token':token})
                time.sleep(300)
        finally:
            print("Ended")

try:
    hostname = socket.getfqdn()
    ip_address = get_ip()
    
    #if there's already a token, cancel this scan and start a new one
    if exists('token'):
        with open('token', 'r') as file:
            token = file.read().rstrip()
        r = post_data("/be/api/scan_fail", {'token':token,'reason':'scanner crashed'})
        sys.exit()

    #register new scan
    r = post_data("/be/api/scan_start", {'hostname':hostname,'ip_address':ip_address})
    if r['status'] != 'success':
        sys.exit("registering did not succeed: " + json.dumps(r))
    token=r['token']
    with open("token", "w") as text_file:
        text_file.write(token)
    hb=HeartbeatTask()
    hb.daemon=True
    hb.start()
    subprocess.check_call('python loki.py --noindicator --dontwait -l loki.out'.split(' '))
    alerts=0
    warnings=0
    notices=0
    with open("loki.out", "r") as results_file:
        lines = results_file.readlines()
        for line in lines:
            res = line.find("Results:")
            if res > -1:
                tmp = line[res:].split()
                alerts=tmp[1]
                warnings=tmp[3]
                notices=tmp[5]
                escaped=re.escape("\n".join(lines))
                r = post_data("/be/api/scan_done", {'token':token,'results':"\n".join(lines),'warnings':warnings, 'alerts':alerts,'notices':notices})
                os.remove('token')
                sys.exit(0)
except Exception as e:
    print("Exception:" + repr(e))
    r = post_data("/be/api/scan_fail", {'token':token,'reason':'Exception:' + repr(e)})
    os.remove('token')
    sys.exit(1)







