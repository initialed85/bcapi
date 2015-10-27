'''
    Name:   bc_discover.py
    Date:   14 Oct 2015
    Author: Edward Beech

    This script generates JSON representing the live state of a Breadcrumb
    network.
'''

# builtins
import sys
import pprint
import time
import datetime
import StringIO
import gzip
import struct
import threading
import copy
import traceback


# local
import Common_pb2  # built from Common.proto (distributed with BCAPI)
import bc_discover
import bc_common
import bc_query


name = sys.argv[0]
name = 'python ' + name if '.py' in name else name

USAGE = """
usage: %s [source IP] [response IP] [trace IP] [role] [password]

e.g.:

%s 192.168.2.1 10.178.64.35 10.113.208.1 ADMIN breadcrumb-admin

or

%s 10.137.137.137 10.137.137.137 10.137.137.137 ADMIN breadcrumb-admin
""" % (name, name, name)

try:
    DISCOVER_SOURCE_IP = sys.argv[1]
    DISCOVER_RESPONSE_IP = sys.argv[2]
    TRACE_IP = sys.argv[3]
    BREADCRUMB_ROLE = sys.argv[4]
    BREADCRUMB_PASSWORD = sys.argv[5]
except:
    print USAGE.strip()
    sys.exit(1)


def discoverer(breadcrumbs, source_ip, response_ip):
    '''
    designed to be spawned as a thread; loops around discovering BCs

    breadcrumbs - breadcrumbs dict
    source_ip - source address to use in multicast probe
    response_ip - ip to tell BCs to respond to
    '''
    pnow = datetime.datetime.now()
    print pnow,  'discoverer started'
    while 1:
        # discover breadcrumbs
        discovered_breadcrumbs = {}
        bc_discover.discover(
            discovered_breadcrumbs,
            timeout=5,
            source_ip=source_ip,
            response_ip=response_ip
        )

        # parse results from discovery
        for k, v in discovered_breadcrumbs.iteritems():
            if k not in breadcrumbs:
                breadcrumbs[k] = {}
            breadcrumbs[k].update({
                'last_seen': datetime.datetime.now(),
                'ip': v['ip'],
            })

        # no sleep needed, bc_discover.discover() blocks for timeout


def gatherer(breadcrumbs, k, trace_ip):
    '''
    designed to be spawned as a thread; loops around and gathers all the BC
    stats

    breadcrumbs - breadcrumbs dict
    k - key for pertinent breadcrumb
    trace_ip - ip address of trace target
    '''
    pnow = datetime.datetime.now()
    print pnow,  'gatherer - started', k
    first_run = True
    stat = {
        'timestamp': None,
        'ip': '',
        'name': '',
        'wireless': {},
        'wired': {},
        'nexthop_mac': '',
        'nexthop_via': ''
    }

    while 1:
        try:
            bc_common.connect(
                breadcrumbs,
                k,
                role='ADMIN',
                password='breadcrumb-admin'
            )
        except:
            pnow = datetime.datetime.now()
            print pnow,  'gatherer - connect failed', k
            time.sleep(5)
            continue
        while 1:
            # build stat structure
            now = datetime.datetime.now()
            stat['timestamp'] = now

            # get complete breadcrumb state first time, set watch for updates
            if first_run:
                # get full state
                try:
                    response = bc_query.get_state(breadcrumbs, k)
                    first_run = False
                except:
                    traceback.print_exc()
                    pnow = datetime.datetime.now()
                    print pnow,  'gatherer - get_state failed', k
                    break

                # setup watch
                try:
                    bc_query.set_watch(
                        breadcrumbs,
                        k,
                        [
                            'system.ipv4',
                            'wired',
                            'wireless',
                            'task',
                            'configuration.saved.general.name'
                        ],
                        8  # watch response interval
                    )
                except:
                    pnow = datetime.datetime.now()
                    print pnow,  'gatherer - set_watch failed', k
                    break

            else:
                # block until watch response received
                try:
                    response = bc_common.recv_msg(breadcrumbs, k).watchResponse
                except:
                    pnow = datetime.datetime.now()
                    print pnow,  'gatherer - recv_msg failed', k
                    break

            # get ip
            stat['ip'] = breadcrumbs[k]['ip']

            # get name
            name = response.state.configuration.saved.general.name
            if name != '':
                stat['name'] = name

            # get wired data
            for wv in response.state.wired:
                try:
                    wmac = ':'.join([
                        str(hex(x)).split('x')[1].zfill(2)
                        for x in struct.unpack("BBBBBB", wv.mac)
                    ])
                except:
                    continue
                if wmac not in stat['wired']:
                    stat['wired'][wmac] = {}
                stat['wired'][wmac].update({
                    'name': wv.name,
                    'rx_bytes': wv.stats.rxBytes,
                    'tx_bytes': wv.stats.txBytes,
                })

            # get wireless data
            for wv in response.state.wireless:
                try:
                    wmac = ':'.join([
                        str(hex(x)).split('x')[1].zfill(2)
                        for x in struct.unpack("BBBBBB", wv.mac)
                    ])
                except:
                    continue
                if wmac not in stat['wireless']:
                    stat['wireless'][wmac] = {'peers': {}}
                stat['wireless'][wmac].update({
                    'name': wv.name,
                    'noise': wv.noise,
                    'channel': wv.channel,
                    'txpower': wv.txpower,
                    'tx_bytes': wv.stats.txBytes,
                    'rx_bytes': wv.stats.rxBytes,
                    'peers': {}
                })
                # get peer data
                for pv in wv.peer:
                    try:
                        pmac = ':'.join([
                            str(hex(x)).split('x')[1].zfill(2)
                            for x in struct.unpack("BBBBBB", pv.mac)
                        ])
                    except:
                        continue
                    if pmac not in stat['wireless'][wmac]['peers']:
                        stat['wireless'][wmac]['peers'][pmac] = {}
                    stat['wireless'][wmac]['peers'][pmac].update({
                        'cost': pv.cost,
                        'rate': pv.rate / 10,
                        'rssi': pv.signal
                    })

            # make sure trace succeeded
            need_to_trace = False
            tasks = {
                v: k for k, v in
                Common_pb2.TaskCommand.TaskAction.items()
            }
            statuses = {
                v: k for k, v in
                Common_pb2.TaskStatus.TaskState.items()
            }
            if tasks[response.state.task.command.action] != 'TRACE':
                pnow = datetime.datetime.now()
                print pnow,  'gatherer - last task not trace', k, '(%s)' % (
                    tasks[response.state.task.command.action]
                )
                need_to_trace = True
            elif statuses[response.state.task.status.state] in [
                                                                'DELAYED',
                                                                'QUEUED',
                                                                'RUNNING'
                                                            ]:
                pnow = datetime.datetime.now()
                print pnow,  'gatherer - trace still underway', k, '(%s)' % (
                    statuses[response.state.task.status.state]
                )
                need_to_trace = False
            elif statuses[response.state.task.status.state] == 'FAILED':
                pnow = datetime.datetime.now()
                print pnow,  'gatherer - trace failed', k, '(%s)' % (
                    statuses[response.state.task.status.state]
                )
                need_to_trace = True
            elif statuses[response.state.task.status.state] == 'SUCCESS':
                # go and get the gzip'd trace dump
                try:
                    response = bc_query.get_file(
                        breadcrumbs,
                        k,
                        response.state.task.status.id
                    )
                except:
                    break
                statuses = {
                    v: k for k, v in
                    Common_pb2.TaskOutputResponse.Status.items()
                }
                if statuses[response.taskOutputResponse.status] != 'SUCCESS':
                    pnow = datetime.datetime.now()
                    print pnow,  'download failed'
                    continue

                # decompress the trace dump
                zfile = StringIO.StringIO()
                zfile.write(response.taskOutputResponse.data)
                zfile.seek(0)
                try:
                    data = gzip.GzipFile(
                        fileobj=zfile, mode='rb'
                    ).read().strip()
                except:
                    traceback.print_exc()
                    pnow = datetime.datetime.now()
                    print pnow,  'gunzip failed'
                    continue

                # parse the trace dump
                lines = data.split('\n')[2:]
                if len(lines) > 0:
                    if 'peer=' in lines[0]:
                        stat['nexthop_via'] = 'mesh'  # mesh/failed backhaul
                        stat['nexthop_mac'] = lines[0].split(
                            'peer='
                        )[1].split('/')[0].lower()
                    else:
                        stat['nexthop_via'] = 'wire'  # ingress/has backhaul
                        stat['nexthop_mac'] = lines[0].split()[2].lower()

                need_to_trace = True

            if need_to_trace:
                # request a trace task (only returns status of request)
                try:
                    response = bc_query.get_trace(breadcrumbs, k, trace_ip)
                    time.sleep(5)
                except:
                    pnow = datetime.datetime.now()
                    print pnow,  'gatherer - get_trace failed', k
                    break

            if 'stats' not in breadcrumbs[k]:
                breadcrumbs[k]['stats'] = []

            breadcrumbs[k]['stats'] += [stat]

            breadcrumbs[k]['stats'] = breadcrumbs[k]['stats'][-2:]

            pnow = datetime.datetime.now()
            print pnow,  'gatherer - got stats for', k

            snooze = 8 - (datetime.datetime.now() - now).total_seconds()

            time.sleep(snooze if snooze >= 0 else 0)

        try:
            bc_common.disconnect(
                breadcrumbs,
                k
            )
        except:
            pnow = datetime.datetime.now()
            print pnow,  'gatherer - connect failed', k
            time.sleep(5)
            continue

        time.sleep(4)


def manager(breadcrumbs, role, password, trace_ip):
    '''
    designed to be spawned as a thread; loops around and manages the health of
    gatherer threads as breadcrumbs are discovered

    breadcrumbs - breadcrumbs dict
    role - role/username to connect to breadcrumbs with
    password - password to connect to breadcrumbs with
    trace_ip - ip address of trace target
    '''
    pnow = datetime.datetime.now()
    print pnow,  'manager started'
    while 1:
        # delete any breadcrumbs that haven't seen seen in a while
        now = datetime.datetime.now()
        for k in breadcrumbs.keys():
            v = breadcrumbs[k]
            if 'last_seen' in v:
                if (now - v['last_seen']).total_seconds() > 30:
                    try:
                        breadcrumbs[k]['conn'].disconnect()
                    except:
                        pass
                    del(breadcrumbs[k])
                    print now,  'manager - deleted gatherer', k

        # try to connect to breadcrumbs as required
        for k in breadcrumbs.keys():
            v = breadcrumbs[k]
            if 'gatherer' in v:
                continue
            # spawn a new gatherer and kick it off
            breadcrumbs[k]['gatherer'] = threading.Thread(
                target=gatherer,
                args=(breadcrumbs, k, trace_ip,)
            )
            breadcrumbs[k]['gatherer'].daemon = True
            breadcrumbs[k]['gatherer'].start()
            time.sleep(0.1)  # debounce

        # use latest stat and second-latest stat to work out bytes per second
        for k in breadcrumbs.keys():
            v = breadcrumbs[k]
            if 'stats' not in v:
                continue
            if len(v['stats']) < 2:
                continue

            stat = copy.deepcopy(v['stats'][-1])

            for ak in ['wired', 'wireless']:
                if ak not in v['stats'][-1]:
                    continue

                t1 = v['stats'][-1]['timestamp']
                t2 = v['stats'][-2]['timestamp']
                diff = (t1 - t2).total_seconds()

                w1 = v['stats'][-1][ak]
                w2 = v['stats'][-2][ak]

                for sk in ['rx_bytes', 'tx_bytes']:
                    temp = {
                        k: {
                            sk: (w1[k][sk] - w2[k][sk]) / diff
                            if w1[k][sk] - w2[k][sk] != 0 else 0
                        }
                        for k in w1
                    }
                    for ik, iv in temp.iteritems():
                        stat[ak][ik].update(iv)

            breadcrumbs[k]['stat'] = copy.deepcopy(stat)

        time.sleep(4)

# init
breadcrumbs = {}

# spawn discoverer
d = threading.Thread(
    target=discoverer,
    args=(breadcrumbs, DISCOVER_SOURCE_IP, DISCOVER_RESPONSE_IP,)
)
d.daemon = True
d.start()
time.sleep(1)

# spawn manager
m = threading.Thread(
    target=manager,
    args=(breadcrumbs, BREADCRUMB_ROLE, BREADCRUMB_PASSWORD, TRACE_IP,)
)
m.daemon = True
m.start()
time.sleep(1)

# init
last_stats = {}

# loop around and dump stats to a file
while 1:
    stats = {}
    for k in breadcrumbs.keys():
        v = breadcrumbs[k]
        if 'stat' in v:
            stats[k] = copy.deepcopy(v['stat'])

    if stats != {} and stats != last_stats:
        print 'writing out'
        with open('./breadcrumb_stats.txt', 'w') as f:
            f.write(pprint.pformat(stats))
        last_stats = stats
    else:
        print 'not writing'

    time.sleep(8)
