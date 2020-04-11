#!/usr/bin/python3

import sys
import logging
import argparse
import time
import grpc
from qrl.generated import qrl_pb2_grpc, qrl_pb2
from google.protobuf import json_format

logging.basicConfig(stream=sys.stdout, level=logging.INFO)

parser = argparse.ArgumentParser(description='Compare the blockchain across two servers.')
parser.add_argument('--hostA', default='127.0.0.1',
                   help='ip address of the node')
parser.add_argument('--portA', default='19009',
                   help='port of the node')
parser.add_argument('--hostB', default='127.0.0.1',
                   help='ip address of the node')
parser.add_argument('--portB', default='19009',
                   help='port of the node')
parser.add_argument('--startBlock', default='0',
                   help='starting block')
parser.add_argument('--endBlock', default='100000',
                   help='ending block')
args = parser.parse_args()

addressA = '{}:{}'.format(args.hostA, args.portA)
channelA = grpc.insecure_channel(addressA)
qrlClientA = qrl_pb2_grpc.PublicAPIStub(channelA)
logging.info('Connected to {}'.format(addressA))

addressB = '{}:{}'.format(args.hostB, args.portB)
channelB = grpc.insecure_channel(addressB)
qrlClientB = qrl_pb2_grpc.PublicAPIStub(channelB)
logging.info('Connected to {}'.format(addressB))

# load the blocks for addressA & addressB
start = time.monotonic()
for blockNum in range(int(args.startBlock), int(args.endBlock)+1):
    request = qrl_pb2.GetObjectReq(query=str(blockNum).encode(encoding='ascii'))
    responseA = qrlClientA.GetObject(request)
    responseB = qrlClientB.GetObject(request)
    if not responseA.HasField('block_extended') or not responseB.HasField('block_extended'):
        # we reached the end of the chain on either A or B
        break

    # update status
    if blockNum > 0 and blockNum % 10000 == 0:
        logging.info('loaded up to {}'.format(blockNum))

    # compare the blocks
    blockA = responseA.block_extended
    blockB = responseB.block_extended

    transactionsA = len(blockA.extended_transactions)
    transactionsB = len(blockB.extended_transactions)
    if transactionsA != transactionsB:
        logging.error('transaction total error at {}'.format(blockNum))
        logging.error(transactionsA, transactionsB)
    transactions = min(transactionsA, transactionsB)

    # handle coinbase
    addressA = blockA.extended_transactions[0].tx.coinbase.addr_to.hex()
    amountA = blockA.extended_transactions[0].tx.coinbase.amount
    addressB = blockB.extended_transactions[0].tx.coinbase.addr_to.hex()
    amountB = blockB.extended_transactions[0].tx.coinbase.amount
    if addressA != addressB:
        logging.error('coinbase address error at {}'.format(blockNum))
        logging.error(addressA, addressB)
    if amountA != amountB:
        logging.error('coinbase amount error at {}'.format(blockNum))
        logging.error(amountA, amountB)

    # handle other transactions
    for txn in range(1, transactions):
        spendA = None
        spendB = None
        addressFromA = blockA.extended_transactions[txn].addr_from.hex()
        feeA = blockA.extended_transactions[txn].tx.fee
        addressFromB = blockB.extended_transactions[txn].addr_from.hex()
        feeB = blockB.extended_transactions[txn].tx.fee
        if addressFromA != addressFromB:
            logging.error('addressFrom error at {}'.format(blockNum))
            logging.error(addressFromA, addressFromB)
        if feeA != feeB:
            logging.error('fee error at {}'.format(blockNum))
            logging.error(feeA, feeB)
        txA = blockA.extended_transactions[txn].tx
        txB = blockB.extended_transactions[txn].tx
        if txA.HasField('transfer') and not txB.HasField('transfer'):
            logging.error('mismatching transfer at {}'.format(blockNum))
            logging.error('missing from B')
        if not txA.HasField('transfer') and txB.HasField('transfer'):
            logging.error('mismatching trasfer at {}'.format(blockNum))
            logging.error('missing from A')
        if txA.HasField('transfer') and txB.HasField('transfer'):
            spendA = txA.transfer
            spendB = txB.transfer
        if txA.HasField('multi_sig_spend') and not txB.HasField('multi_sig_spend'):
            logging.error('mismatching multi_sig_spend at {}'.format(blockNum))
            logging.error('missing from B')
        if not txA.HasField('multi_sig_spend') and txB.HasField('multi_sig_spend'):
            logging.error('mismatchign multi_sig_spend at {}'.format(blockNum))
            logging.error('missing from A')
        if txA.HasField('multi_sig_spend') and txB.HasField('multi_sig_spend'):
            spendA = txA.transfer
            spendB = txB.transfer
        if spendA is not None and spendB is not None:
            addressListA = txA.transfer.addrs_to
            amountListA = txA.transfer.amounts
            addressListB = txB.transfer.addrs_to
            amountListB = txB.transfer.amounts
            addressToLenA = len(addressListA)
            addressToLenB = len(addressListB)
            amountToLenA = len(amountListA)
            amountToLenB = len(amountListB)
            if addressToLenA != addressToLenB:
                logging.error('addressToLen error at {}'.format(blockNum))
                logging.error(addressToLenA, addressToLenB)
            addressToLen = min(addressToLenA, addressToLenB)
            if amountToLenA != amountToLenB:
                logging.error('amountToLen error at {}'.format(blockNum))
                logging.error(amountToLenA, amountToLenB)
            for i in range(0, addressToLen):
                addressA = addressListA[i].hex()
                amountA = amountListA[i]
                addressB = addressListB[i].hex()
                amountB = amountListB[i]
                if addressA != addressB:
                    logging.error('address error at {}'.format(blockNum))
                    logging.error(addressA, addressB)
                if amountA != amountB:
                    logging.error('amount error at {}'.format(blockNum))
                    logging.error(amountA, amountB)

end = time.monotonic()

elapsed = int(end - start)
logging.info('compared up to block number {} in {} seconds'.format(blockNum, elapsed))
