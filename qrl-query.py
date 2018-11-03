#!/usr/bin/python3

import sys
import logging
import argparse
import grpc
from qrl.generated import qrl_pb2_grpc, qrl_pb2
from google.protobuf import json_format

logging.basicConfig(stream=sys.stdout, level=logging.INFO)

# arguments
parser = argparse.ArgumentParser(description='Query an object from a provided QRL node such as a block number, transaction hash, or address',
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('--host', default='127.0.0.1',
                   help='ip address of the node')
parser.add_argument('--port', default='19009',
                   help='port of the node')
parser.add_argument('object',
                   help='what to query (block number, tx, address)')
args = parser.parse_args()

# Determine if we are querying something sensible
queryString = None
if len(args.object) == 79 and args.object.startswith('Q'):
    logging.info('Query of address detected')
    queryString = bytes.fromhex(args.object[1:])
elif len(args.object) == 64:
    logging.info('Query of tx detected')
    queryString = bytes.fromhex(args.object)
elif args.object.isnumeric():
    logging.info('Query of block number detected')
    queryString = args.object.encode(encoding='ascii')
else:
    logging.error('Please provide a valid object to query')

# There is something sensible to query so connect and make the request
if queryString is not None:
    address = '{}:{}'.format(args.host, args.port)
    channel = grpc.insecure_channel(address, options=[('grpc.max_receive_message_length', 4194304*2)])
    qrlClient = qrl_pb2_grpc.PublicAPIStub(channel)
    logging.info('Connected to {}'.format(address))
    request = qrl_pb2.GetObjectReq(query=queryString)
    response = qrlClient.GetObject(request)
    if response.found:
        logging.info('Response:{}'.format(
            json_format.MessageToJson(
                response,
                including_default_value_fields=True, preserving_proto_field_name=True, sort_keys=True)
            )
        )
    else:
        logging.info('Object not found')
