#!/usr/bin/python3

import sys
import logging
import argparse
import time
import grpc
from qrl.generated import qrl_pb2_grpc, qrl_pb2

public_api_port = 19009

def define_args():
    parser = argparse.ArgumentParser(description='Peers',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    return parser.parse_args()

# main
logging.basicConfig(stream=sys.stdout, level=logging.INFO)

args = define_args()
clients = []

def get_peers(ip):
    channel = grpc.insecure_channel('{}:{}'.format(ip,public_api_port))
    client = qrl_pb2_grpc.PublicAPIStub(channel)
    req = qrl_pb2.GetKnownPeersReq()
    try:
        resp = client.GetKnownPeers(req, timeout=2)
        for peer in resp.known_peers:
            newip = peer.ip.split(':')[0]
            if newip not in peers:
                logging.debug('New Peer found: {}'.format(newip))
                peers.add(newip)
                get_peers(newip)
    except:
        unresponsive_peers.add(ip)

peers = set(['127.0.0.1'])
unresponsive_peers = set()
get_peers('127.0.0.1')
good_peers = peers - unresponsive_peers
logging.info('Total good_peers: {}'.format(len(good_peers)))
logging.info(good_peers)
logging.info('Total unresponsive_peers: {}'.format(len(unresponsive_peers)))
logging.info(unresponsive_peers)
