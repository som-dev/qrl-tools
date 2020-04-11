#!/usr/bin/python3

import sys
import logging
import argparse
import grpc
from qrl.generated import qrl_pb2_grpc, qrl_pb2
from google.protobuf import json_format

logging.basicConfig(stream=sys.stdout, level=logging.INFO)

def log_msg(prefix, msg):
    logging.info('{}:{}'.format(
        prefix,
        json_format.MessageToJson(
            msg,
            including_default_value_fields=True, preserving_proto_field_name=True, sort_keys=True)
        )
    )

def query_addr(qrl_client, addr):
    request = qrl_pb2.GetObjectReq(query=bytes.fromhex(addr[1:]))
    response = qrl_client.GetObject(request)
    log_msg('',response)
    if addr.startswith('Q1'):
        request = qrl_pb2.GetMultiSigAddressStateReq(address=bytes.fromhex(addr[1:]))
        response = qrl_client.GetMultiSigAddressState(request)
        log_msg('',response)
        request = qrl_pb2.GetMultiSigSpendTxsByAddressReq(address=bytes.fromhex(addr[1:]), item_per_page=8, page_number=1,
                                                          filter_type=qrl_pb2.GetMultiSigSpendTxsByAddressReq.NONE)
        response = qrl_client.GetMultiSigSpendTxsByAddress(request)
        log_msg('',response)
    else:
        request = qrl_pb2.GetAddressStateReq(address=bytes.fromhex(addr[1:]))
        response = qrl_client.GetAddressState(request)
        log_msg('',response)

def query_txn(qrl_client, txn):
    #request = qrl_pb2.GetTransactionReq(tx_hash=bytes.fromhex(txn))
    #response = qrl_client.GetTransaction(request)
    request = qrl_pb2.GetObjectReq(query=bytes.fromhex(txn))
    response = qrl_client.GetObject(request)
    log_msg('',response)
    if response.found and response.transaction.tx.HasField('multi_sig_spend'):
        vote_req = qrl_pb2.GetVoteStatsReq(multi_sig_spend_tx_hash=response.transaction.tx.transaction_hash)
        vote_resp = qrl_client.GetVoteStats(vote_req)
        log_msg('',vote_resp)

def query_block(qrl_client, block):
    #request = qrl_pb2.GetBlockByNumberReq(block_number=block)
    #response = qrl_client.GetBlockByNumber(request)
    request = qrl_pb2.GetObjectReq(query=str(block).encode(encoding='ascii'))
    response = qrl_client.GetObject(request)
    log_msg('',response)

def get_stats(qrl_client):
    request = qrl_pb2.GetStatsReq()
    response = qrl_client.GetStats(request)
    log_msg('',response)

# arguments
parser = argparse.ArgumentParser(description='Query an object from a provided QRL node such as a block number, transaction hash, or address',
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('--host', default='127.0.0.1',
                   help='ip address of the node')
parser.add_argument('--port', default='19009',
                   help='port of the node')
parser.add_argument('--show_request', action='store_true', default=False,
                   help='display outgoing query message')
parser.add_argument('object',
                   help='what to query, such as [block number], [txhash], [Q-address], stats')
args = parser.parse_args()

address = '{}:{}'.format(args.host, args.port)
channel = grpc.insecure_channel(address, options=[('grpc.max_receive_message_length', 4194304*2)])
qrl_client = qrl_pb2_grpc.PublicAPIStub(channel)
logging.info('Connected to {}'.format(address))


# Determine if we are querying something sensible
if len(args.object) == 79 and args.object.startswith('Q'):
    logging.info('Query of address detected')
    query_addr(qrl_client, args.object)
elif len(args.object) == 64:
    logging.info('Query of tx detected')
    query_txn(qrl_client, args.object)
elif args.object.isnumeric():
    logging.info('Query of block number detected')
    query_block(qrl_client, int(args.object))
elif args.object == 'stats':
    query_stats(qrl_client)
else:
    logging.error('Please provide a valid object to query')
