'''
    Name:   bc_common.py
    Date:   9 Oct 2015
    Author: Edward Beech

    This script is designed to duck out and query all the specified BCs for
    their state information (everything relevant).
'''

# builtins
import ssl
import socket
import struct
import hashlib
import traceback
import pprint
import gzip
import StringIO
import zlib

# external
import Message_pb2  # built from Message.proto (distributed with BCAPI)


def gzip_decompress(zdata):
    '''
    decompress a string with gzip (differs from zlib)

    zdata - string to decompress
    '''
    return zlib.decompress(zdata, -15)  # magic, I sure don't understand zlib


def deconstruct_packet(packet):
    '''
    strip the header from the packet, return the data

    packet - the packet
    '''

    # TODO: something with this (e.g. catch decompression)
    header = struct.unpack(
        '>ibbbb',
        packet[0:8]
    )

    data = packet[8:]

    # print 'RX', header, len(data)

    if header[1] == 2:
        data = gzip_decompress(data)

    return data


def construct_packet(data, gzip):
    '''
    build the header, attach it to the data, return it

    data - the data
    '''

    if gzip:
        data = gzip_compress(data)

    header = struct.pack(
        '>ibbbb',
        len(data),
        2 if gzip else 0,
        0,
        0,
        0
    )

    # print 'TX', [len(data), 2 if gzip else 0, 0, 0, 0], len(data)

    packet = header + data

    return packet


def build_msg(breadcrumbs, k):
    '''
    build and return an empty message to go the specified breadcrumb`

    breadcrumbs - breadcrumbs dict'
    k - key for pertinent breadcrumb
    '''
    msgTx = Message_pb2.BCMessage()
    msgTx.sequenceNumber = breadcrumbs[k]['sequenceNumber']
    return msgTx


def send_msg(breadcrumbs, k, msgTx, gzip=False):
    '''
    send a message to the specified breadcrumb

    breadcrumbs - breadcrumbs dict
    k - key for pertinent breadcrumb
    msgTx - Message_pb2.BCMessage object
    '''
    packetTx = construct_packet(msgTx.SerializeToString(), gzip=gzip)
    breadcrumbs[k]['conn'].send(packetTx)
    breadcrumbs[k]['sequenceNumber'] += 1
    # print msgTx, '\n---- ---- ---- ----\n'


def recv_msg(breadcrumbs, k):
    '''
    receive and return a message from the specified breadcrumb

    breadcrumbs - breadcrumbs dict'
    k - key for pertinent breadcrumb
    '''
    packetRx = breadcrumbs[k]['conn'].recv(65535)
    dataRx = deconstruct_packet(packetRx)
    msgRx = Message_pb2.BCMessage()
    msgRx.ParseFromString(dataRx)
    # print msgRx, '\n---- ---- ---- ----\n'
    return msgRx


def connect(breadcrumbs, k, role='ADMIN', password='breadcrumb-admin'):
    '''
    connect to the specified breadcrumb

    breadcrumbs - breadcrumbs dict
    k - key for pertinent breadcrumb
    role - username to use
    password - password to use
    '''
    # rig up SSL socket with 30 second timeout
    s = socket.socket(socket.AF_INET)
    s.settimeout(30)
    breadcrumbs[k]['conn'] = ssl.wrap_socket(s)
    breadcrumbs[k]['conn'].connect((breadcrumbs[k]['ip'], 2300))

    # remote end sends a challenge packet after connection
    msgRx = recv_msg(breadcrumbs, k)

    # make a start on the breadcrumb dict
    serial = str(msgRx.auth.serial)
    breadcrumbs[serial].update({
        'serial': serial,
        'ip': breadcrumbs[k]['ip'],
        'authenticated': False,
        'sequenceNumber': msgRx.sequenceNumber + 1
    })

    # build and send the challenge response
    msgTx = build_msg(breadcrumbs, k)
    actions = {k: v for k, v in Message_pb2.BCMessage.Auth.Action.items()}
    roles = {k: v for k, v in Message_pb2.Common_pb2.Role.items()}
    msgTx.auth.action = actions['LOGIN']
    msgTx.auth.role = roles['ADMIN']
    response = password + msgRx.auth.challengeOrResponse
    response_hash = hashlib.sha384(response).digest()
    msgTx.auth.challengeOrResponse = response_hash
    msgTx.auth.compressionMask = 0 | 2
    send_msg(breadcrumbs, k, msgTx, gzip=False)

    # receive the response to the challenge response
    msgRx = recv_msg(breadcrumbs, k)

    # if response was successful, add to the breadcrumb dictionary
    statuses = {v: k for k, v in msgRx.Result.Status.items()}
    status = statuses[msgRx.authResult.status]
    if status == 'SUCCESS':
        breadcrumbs[serial].update({
            'authenticated': True
        })


def disconnect(breadcrumbs, k):
    '''
    disconnect from the specified breadcrumb
    '''
    if k in breadcrumbs:
        breadcrumbs[k]['conn'].close()
        del(breadcrumbs[k])

if __name__ == '__main__':
    # if not invoked as a module
    breadcrumbs = {}
    pass
