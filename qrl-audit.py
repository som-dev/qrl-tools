#!/usr/bin/python3

import sys
import logging
import argparse
import time
import grpc
import binascii
from qrl.generated import qrl_pb2_grpc, qrl_pb2
from google.protobuf import json_format
from qrl.crypto.misc import merkle_tx_hash
from qrl.crypto.misc import sha256
from pyqrllib.pyqrllib import XmssFast

def DefineArgs():
    parser = argparse.ArgumentParser(description='Scans the blockchain from a provided QRL node',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--host', default='127.0.0.1',
                       help='ip address of the node')
    parser.add_argument('--port', default='19009',
                       help='port of the node')
    parser.add_argument('type',
                       help='what to audit (chain, address, tx)')
    parser.add_argument('object', nargs='?',
                       help='specific address or tx')
    return parser.parse_args()

def ValidateArgs(args):
    validArgs = False
    if args.type == 'address':
        if not args.object:
            logging.error('Must provide a specific address')
        elif len(args.object) != 79 or not args.object.startswith('Q'):
            logging.error('Must provide a valid address')
        else:
            validArgs = True
    elif args.type == 'tx':
        if not args.object:
            logging.error('Must provide a specific tx')
        elif len(args.object) != 64:
            logging.error('Must provide a valid tx')
        else:
            validArgs = True
    elif args.type == 'chain':
        validArgs = True
    else:
        logging.error('Unknown type to audit: {}'.format(args.type))
    return validArgs

def ConnectClient(address):
    channel = grpc.insecure_channel(address, options=[('grpc.max_receive_message_length', 4194304*2)])
    return qrl_pb2_grpc.PublicAPIStub(channel)

def AuditAddress(qrlClient, addr, printSummary=True):
    balance = -1
    request_addr = qrl_pb2.GetObjectReq(query=bytes.fromhex(addr[1:]))
    response_addr = qrlClient.GetObject(request_addr)
    if not response_addr.HasField('address_state'):
        logging.error('could not find address {}'.format(addr))
    else:
        balance = response_addr.address_state.balance
        if (printSummary):
                logging.info('balance: {}'.format(balance))
                logging.info('found {} transactions'.format(len(response_addr.address_state.transaction_hashes)))
        bad_tx_count = 0
        for txn in range(0, len(response_addr.address_state.transaction_hashes)):
            txhash = response_addr.address_state.transaction_hashes[txn].hex()
            request_tx = qrl_pb2.GetObjectReq(query=bytes.fromhex(txhash))
            response_tx = qrlClient.GetObject(request_tx)

            if not response_tx.HasField('transaction'):
                bad_tx_count += 1
                logging.error('txhash {} for addr {} does not exist'.format(txhash, addr))
            else:
                if response_tx.transaction.tx.HasField('transfer'):
                    master_addr = response_tx.transaction.tx.master_addr
                    fee = response_tx.transaction.tx.fee.to_bytes(8, byteorder='big', signed=False)
                    tmptxhash = (master_addr + fee)
                    for index in range(0, len(response_tx.transaction.tx.transfer.addrs_to)):
                        addr_to = response_tx.transaction.tx.transfer.addrs_to[index]
                        amount = response_tx.transaction.tx.transfer.amounts[index].to_bytes(8, byteorder='big', signed=False)
                        tmptxhash = (tmptxhash + addr_to + amount)

                    data_hash = sha256(tmptxhash)
                    signature = response_tx.transaction.tx.signature
                    public_key = response_tx.transaction.tx.public_key

                    if not XmssFast.verify(data_hash, signature, public_key):
                        logging.info('txhash {} for addr {} failed XmssFast verification'.format(txhash, addr))

        if (printSummary):
            if bad_tx_count > 0:
                logging.info('Could not retrieve {} transactions'.format(bad_tx_count))
            else:
                logging.info('No unknown transactions')

    return balance

def AuditChain(qrlClient):
    totalBlockNum = 0
    blockStore = {}
    balanceByAddressStore = {}
    transactionStore = {}

    # load the blocks
    while True:
        request = qrl_pb2.GetObjectReq(query=str(totalBlockNum).encode(encoding='ascii'))
        response = qrlClient.GetObject(request)
        if not response.HasField('block_extended'):
            # we reached the end of the chain
            break

        # get and store block
        block = response.block_extended
        blockStore[totalBlockNum] = block
        totalBlockNum += 1

    logging.info('loaded up to block number {}'.format(totalBlockNum))

    # re-create balances by replaying each block
    for blockNum in range(0, totalBlockNum):
        block = blockStore[blockNum]

        # store transactions in each block
        for txn in range(0, len(block.extended_transactions)):
            txhash = block.extended_transactions[txn].tx.transaction_hash.hex()
            transactionStore[txhash] = block.extended_transactions[txn]

        # handle coinbase
        address = block.extended_transactions[0].tx.coinbase.addr_to.hex()
        amount = block.extended_transactions[0].tx.coinbase.amount
        if not address in balanceByAddressStore:
            balanceByAddressStore[address] = 0
        balanceByAddressStore[address] += amount

        # handle all other transactions outside of coinbase
        for txn in range(1, len(block.extended_transactions)):
            addressFrom = block.extended_transactions[txn].addr_from.hex()
            fee = block.extended_transactions[txn].tx.fee
            if (fee > 0):
                balanceByAddressStore[addressFrom] -= fee
            tx = block.extended_transactions[txn].tx
            if (tx.HasField('transfer')):
                addressList = tx.transfer.addrs_to
                amountList = tx.transfer.amounts
                for i in range(0, len(addressList)):
                    address = addressList[i].hex()
                    amount = amountList[i]
                    if not address in balanceByAddressStore:
                        balanceByAddressStore[address] = 0
                    balanceByAddressStore[address] += amount
                    balanceByAddressStore[addressFrom] -= amount

    logging.info('loaded {} addresses and {} transactions'.format(len(balanceByAddressStore), len(transactionStore)))

    # audit each block, checking the block header and building a list
    for blockNum in range(0, totalBlockNum):
        block = blockStore[blockNum]
        if blockNum > 0:
            blockPrev = blockStore[blockNum-1]
            if block.header.hash_header_prev != blockPrev.header.hash_header:
                logging.error('prev block error at {}'.format(blockNum))
            if block.header.timestamp_seconds < blockPrev.header.timestamp_seconds:
                logging.error('timestamp error at {}'.format(blockNum))
        if block.header.block_number != blockNum:
            logging.error('block num error at {}'.format(blockNum))
        hashedtransactions = [block.extended_transactions[0].tx.transaction_hash]
        reward = block.header.reward_block
        for txn in range(1, len(block.extended_transactions)):
            reward += block.extended_transactions[txn].tx.fee
            hashedtransactions.append(block.extended_transactions[txn].tx.transaction_hash)
        if block.extended_transactions[0].tx.coinbase.amount != reward:
            logging.error('coinbase error at {}'.format(blockNum))
        if block.header.reward_fee + block.header.reward_block != reward:
            logging.error('reward error at {}'.format(blockNum))
        merkle_root = merkle_tx_hash(hashedtransactions)
        if block.header.merkle_root != merkle_root:
            logging.error('merkle_root error at {}'.format(blockNum))

    for addr in balanceByAddressStore:
        try:
            balance = AuditAddress(qrlClient, 'Q'+addr, False)
            if balance != balanceByAddressStore[addr]:
                logging.error('balance for {} does not match'.format('Q'+addr))
                logging.error('node-reported balance: {}'.format(balance))
                logging.error('calculated balance:    {}'.format(balanceByAddressStore[addr]))
        except:
            logging.error('could not query addr {}'.format('Q'+addr))
            raise

# main
logging.basicConfig(stream=sys.stdout, level=logging.INFO)

args = DefineArgs()
if not ValidateArgs(args):
    sys.exit()

address = '{}:{}'.format(args.host, args.port)
qrlClient = ConnectClient(address)
logging.info('Connected to {} '.format(address))

start = time.monotonic()

if args.type == 'address':
    AuditAddress(qrlClient, args.object)
elif args.type == 'chain':
    AuditChain(qrlClient)

end = time.monotonic()
elapsed = end - start
logging.info('elapsed time: {} seconds'.format(elapsed))
