'''
    Name:   bc_discover.py
    Date:   9 Oct 2015
    Author: Edward Beech

    This script is designed to duck out and discover all the BCs on a the
    local network.
'''

# builtins
import fcntl
import struct
import socket
import threading
import time
import pprint
import traceback

# external
import Sup_pb2  # built from Sub.proto (distributed with BCAPI)


def get_ip_address(ifname):
    '''
    get IP of an interface - thanks stackoverflow

    ifname - interface to get IP for
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])


def listenSup(s, breadcrumbs, size=256):
    '''
    listen for Sup messages (BC discovery protocol)

    s - socket object to listen for Sup messages
    breadcrumbs - dictionary to store discovered BCs in
    size - max size of response for socket
    '''

    while 1:
        dataRx, addrRx = s.recvfrom(size)  # blocking
        msgSup = Sup_pb2.SupMessage()
        try:
            msgSup.ParseFromString(dataRx)
        except:
            continue

        breadcrumb = {'ip': addrRx[0]}
        for p in msgSup.properties:
            (k, v) = (p.key, str(p.value))
            if k in ['SERIAL']:
                breadcrumb['serial'] = v
            elif k in ['NETWORK']:
                breadcrumb['essid'] = v
            elif k in ['LOCAL']:
                breadcrumb['local'] = True if v == 'Y' else False

        if breadcrumb['serial'] not in breadcrumbs:
            breadcrumbs[breadcrumb['serial']] = {}
        breadcrumbs[breadcrumb['serial']].update(breadcrumb)


def discover(breadcrumbs, timeout=5, source_ip='', response_ip=''):
    '''
    discover breadcrumbs

    timeout - how long to wait for responses
    source_ip - the IP to send the multicast discovery from
    response_ip - the IP to tell the Breadcrumbs to respond to
    '''

    if source_ip == '' and response_ip == '':
        own_ip = '127.0.0.1'
        for n in ['eth0', 'br-lan', 'en7', 'en0']:
            try:
                own_ip = get_ip_address(n)
            except:
                pass

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    s.setsockopt(
        socket.SOL_IP,
        socket.IP_MULTICAST_IF,
        socket.inet_aton(source_ip)
    )

    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)

    l = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    l.bind(('', 35058))

    listenerSup = threading.Thread(
        target=listenSup,
        args=(l, breadcrumbs, )
    )
    listenerSup.daemon = True
    listenerSup.start()

    msgSup = Sup_pb2.SupMessage()

    msgSup.header = msgSup.header  # protobuf header unset otherwise; weird
    msgSup.messageType = msgSup.REQUEST
    msgSup.otherAddress = response_ip
    msgSup.otherPort = 35058
    msgSup.service = '*'

    dataSup = msgSup.SerializeToString()

    s.sendto(dataSup, ('224.0.0.224', 35057))

    time.sleep(timeout)

    del(listenerSup)


if __name__ == '__main__':
    # if not invoked as a module, go do a discovery
    breadcrumbs = {}
    pprint.pprint(discover())
