'''
    Name:   bc_state.py
    Date:   9 Oct 2015
    Author: Edward Beech

    This script is designed to duck out and query all the specified BCs for
    their state information (everything relevant).
 '''

# builtins
import ssl
import socket
import zlib
import struct
import hashlib
import traceback
import pprint

# external
import Message_pb2  # built from Message.proto (distributed with BCAPI)

# related
import bc_common


def get_state(breadcrumbs, k):
    '''
    build a state request message, send and return the result

    breadcrumbs - breadcrumbs dict
    k - key for pertinent breadcrumb
    '''
    msgTx = bc_common.build_msg(breadcrumbs, k)
    msgTx.state.Clear()
    bc_common.send_msg(breadcrumbs, k, msgTx)

    msgRx = bc_common.recv_msg(breadcrumbs, k)

    return msgRx


def get_trace(breadcrumbs, k, ip):
    '''
    build a trace request message, send and return the result

    breadcrumbs - breadcrumbs dict
    k - key for pertinent breadcrumb
    '''
    msgTx = bc_common.build_msg(breadcrumbs, k)
    tasks = {
        k: v for
        k, v in
        Message_pb2.Common_pb2.TaskCommand.TaskAction.items()
    }
    msgTx.runTask.action = tasks['TRACE']
    msgTx.runTask.arguments = ip
    bc_common.send_msg(breadcrumbs, k, msgTx)

    msgRx = bc_common.recv_msg(breadcrumbs, k)

    return msgRx


def get_file(breadcrumbs, k, task_id):
    '''
    build a file download request message, send and return the result

    breadcrumbs - breadcrumbs dict
    k - key for pertinent breadcrumb
    '''
    msgTx = bc_common.build_msg(breadcrumbs, k)
    msgTx.taskOutputRequest.position = 0
    msgTx.taskOutputRequest.maximumDataSize = 65535
    msgTx.taskOutputRequest.id = task_id
    bc_common.send_msg(breadcrumbs, k, msgTx)

    msgRx = bc_common.recv_msg(breadcrumbs, k)

    return msgRx


def set_watch(breadcrumbs, k, watches, interval=5):
    '''
    build a watch request message, send and return the result

    breadcrumbs - breadcrumbs dict
    k - key for pertinent breadcrumb
    watches - list of BCMessage paths to watch (assuming state. prefix)
    interval - interval to ask for them to be watch
    '''
    msgTx = bc_common.build_msg(breadcrumbs, k)
    for w in watches:
        watchObj = msgTx.watchRequest.watchObject.add()
        watchObj.messagePath = w
        watchObj.interval = interval

    bc_common.send_msg(breadcrumbs, k, msgTx)

    msgRx = bc_common.recv_msg(breadcrumbs, k)

    return msgRx


def set_name(breadcrumbs, k, name):
    '''
    change the name of a breadcrumb

    breadcrumbs - breadcrumbs dict
    k - key for pertinent breadcrumb
    name - new name for breadcrumb
    '''
    msgTx = bc_common.build_msg(breadcrumbs, k)
    msgTx.config.general.name = name

    bc_common.send_msg(breadcrumbs, k, msgTx)

    msgRx = bc_common.recv_msg(breadcrumbs, k)

    return msgRx


def reboot(breadcrumbs, k):
    '''
    reboot a breadcrumb

    breadcrumbs - breadcrumbs dict
    k - key for pertinent breadcrumb
    '''
    msgTx = bc_common.build_msg(breadcrumbs, k)
    tasks = {
        k: v for
        k, v in
        Message_pb2.Common_pb2.TaskCommand.TaskAction.items()
    }
    msgTx.runTask.action = tasks['REBOOT']

    bc_common.send_msg(breadcrumbs, k, msgTx)

    msgRx = bc_common.recv_msg(breadcrumbs, k)

    return msgRx

if __name__ == '__main__':
    # if not invoked as a module
    breadcrumbs = {}
    pass
