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


def define_args():
    parser = argparse.ArgumentParser(description='Scans the blockchain from a provided QRL node',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--host', default='127.0.0.1',
                       help='ip address of the node')
    parser.add_argument('--port', default='19009',
                       help='port of the node')
    parser.add_argument('type',
                       help='what to audit (chain or address)')
    parser.add_argument('object', nargs='?',
                       help='specific address or tx')
    return parser.parse_args()


def validate_args(args):
    valid_args = False
    if args.type == 'address':
        if not args.object:
            logging.error('Must provide a specific address')
        elif len(args.object) != 79 or not args.object.startswith('Q'):
            logging.error('Must provide a valid address')
        else:
            valid_args = True
    elif args.type == 'tx':
        if not args.object:
            logging.error('Must provide a specific tx')
        elif len(args.object) != 64:
            logging.error('Must provide a valid tx')
        else:
            valid_args = True
    elif args.type == 'chain':
        valid_args = True
    else:
        logging.error('Unknown type to audit: {}'.format(args.type))
    return valid_args


def connect_client(address):
    """ Connect to the remote client """
    channel = grpc.insecure_channel(address, options=[('grpc.max_receive_message_length', 4194304*8)])
    return qrl_pb2_grpc.PublicAPIStub(channel)


def is_multisig(addr):
    """ Returns true if the provided address is a multi sig address """
    return addr.startswith('Q1')


def to_bytes(value):
    """ returns 8-byte big-endian byte order of provided value """
    return value.to_bytes(8, byteorder='big', signed=False)


def get_tx_hash(spend):
    """ builds up bytes for a spend used in verifying signatures """
    tx_hash = bytes()
    for index in range(0, len(spend.addrs_to)):
        tx_hash += (spend.addrs_to[index] + to_bytes(spend.amounts[index]))
    return tx_hash


def audit_multisig_addr(qrl_client, addr):
    """ Validate the multi sig address """
    balance = 0
    tx_count = 0
    bad_tx_count = 0
    request_addr = qrl_pb2.GetMultiSigAddressStateReq(address=bytes.fromhex(addr[1:]))
    response_addr = qrl_client.GetMultiSigAddressState(request_addr)
    if not response_addr.HasField('state'):
        logging.error('could not find address {}'.format(addr))
        return balance, tx_count, bad_tx_count
    balance = response_addr.state.balance
    request_txs = qrl_pb2.GetMultiSigSpendTxsByAddressReq(address=bytes.fromhex(addr[1:]), item_per_page=64, page_number=1,
                                                         filter_type=qrl_pb2.GetMultiSigSpendTxsByAddressReq.EXECUTED_ONLY)
    response_txs = qrl_client.GetMultiSigSpendTxsByAddress(request_txs)
    tx_count = len(response_txs.transactions_detail)
    for tx_detail in response_txs.transactions_detail:
        tx = tx_detail.tx
        if not tx.HasField('multi_sig_spend'):
            bad_tx_count += 1
            logging.error('txhash {} for addr {} does not exist'.format(tx.transaction_hash.hex(), addr))
            continue
        tmptxhash = (tx.master_addr + to_bytes(tx.fee)
                   + tx.multi_sig_spend.multi_sig_address + to_bytes(tx.multi_sig_spend.expiry_block_number)
                   + get_tx_hash(tx.multi_sig_spend))
        if not XmssFast.verify(sha256(tmptxhash), tx.signature, tx.public_key):
            logging.info('txhash {} for addr {} failed XmssFast verification'.format(tx.transaction_hash.hex(), addr))
    return balance, tx_count, bad_tx_count

def audit_regular_addr(qrl_client, addr):
    """ Validate the provided regular address """
    balance = 0
    tx_count = 0
    bad_tx_count = 0
    request_addr = qrl_pb2.GetAddressStateReq(address=bytes.fromhex(addr[1:]))
    response_addr = qrl_client.GetAddressState(request_addr)
    if not response_addr.HasField('state'):
        logging.error('could not find address {}'.format(addr))
        return balance, tx_count, bad_tx_count
    balance = response_addr.state.balance
    tx_count = len(response_addr.state.transaction_hashes)
    for txhash in response_addr.state.transaction_hashes:
        request_tx = qrl_pb2.GetObjectReq(query=bytes.fromhex(txhash.hex()))
        response_tx = qrl_client.GetObject(request_tx)
        if not response_tx.HasField('transaction'):
            bad_tx_count += 1
            logging.error('txhash {} for addr {} does not exist'.format(txhash, addr))
            continue
        tx = response_tx.transaction.tx
        if tx.HasField('transfer') or tx.HasField('multi_sig_spend'):
            tmptxhash = (tx.master_addr + to_bytes(tx.fee))
            if tx.HasField('transfer'):
                tmptxhash += (tx.transfer.message_data + get_tx_hash(tx.transfer))
            if tx.HasField('multi_sig_spend'):
                tmptxhash += (tx.multi_sig_spend.multi_sig_address
                            + to_bytes(tx.multi_sig_spend.expiry_block_number)
                            + get_tx_hash(tx.multi_sig_spend))
            data_hash = sha256(tmptxhash)
            signature = tx.signature
            public_key = tx.public_key
            if not XmssFast.verify(data_hash, signature, public_key):
                logging.info('txhash {} for addr {} failed XmssFast verification'.format(txhash, addr))
    return balance, tx_count, bad_tx_count


def audit_address(qrl_client, addr, printSummary=True):
    """ Validate the provided address """
    if is_multisig(addr):
        balance, tx_count, bad_tx_count = audit_multisig_addr(qrl_client, addr)
    else:
        balance, tx_count, bad_tx_count = audit_regular_addr(qrl_client, addr)
    if (printSummary):
        logging.info('balance: {}'.format(balance))
        logging.info('found {} transactions'.format(tx_count))
        if bad_tx_count > 0:
            logging.info('Could not retrieve {} transactions'.format(bad_tx_count))
        else:
            logging.info('No unknown transactions')
    return balance


def has_multi_sig_spend_executed(qrl_client, tx_hash):
    """ Check if the multi_sig_spend transaction has executed """
    vote_req = qrl_pb2.GetVoteStatsReq(multi_sig_spend_tx_hash=tx_hash)
    vote_resp = qrl_client.GetVoteStats(vote_req)
    if vote_resp.HasField('vote_stats'):
        return vote_resp.vote_stats.executed
    return False


def update_balances(balances_store, addr_from, spend, dbg_addr, tx_hash):
    """ Move the amounts from addr_from into one or more addr_to """
    for i in range(0, len(spend.addrs_to)):
        addr_to = spend.addrs_to[i].hex()
        amount = spend.amounts[i]
        if not addr_to in balances_store:
            balances_store[addr_to] = 0
        balances_store[addr_to] += amount
        balances_store[addr_from] -= amount
        if dbg_addr in [addr_to, addr_from]:
            print('tx amnt {} Q{} -> Q{} via tx {}'.format(amount, addr_from, addr_to, tx_hash))


def audit_chain(qrl_client, dbg_addr):
    """
    Request and store each blockself.
    Iterate thru each block, replaying each transaction to recreate address balances.
    Query each address comparing the reported vs calculated balances.
    """
    total_blocks = 0
    block_store = dict()
    balances_store = dict()
    transaction_store = dict()
    if dbg_addr is not None:
        dbg_addr = bytes.fromhex(dbg_addr[1:]).hex()
    # load the blocks
    while True:
        request = qrl_pb2.GetObjectReq(query=str(total_blocks).encode(encoding='ascii'))
        response = qrl_client.GetObject(request)
        if not response.HasField('block_extended'):
            # we reached the end of the chain
            break
        # get and store block
        block = response.block_extended
        block_store[total_blocks] = block
        total_blocks += 1

    logging.info('loaded up to block number {}'.format(total_blocks))

    # re-create balances by replaying each block
    for block_num in range(0, total_blocks):
        block = block_store[block_num]

        # store transactions in each block
        for txn in range(0, len(block.extended_transactions)):
            txhash = block.extended_transactions[txn].tx.transaction_hash.hex()
            transaction_store[txhash] = block.extended_transactions[txn]

        # handle coinbase
        address = block.extended_transactions[0].tx.coinbase.addr_to.hex()
        amount = block.extended_transactions[0].tx.coinbase.amount
        if not address in balances_store:
            balances_store[address] = 0
        balances_store[address] += amount
        if dbg_addr in [address]:
            print('coinbase amnt {} -> Q{} via blk {}'.format(amount, address, block_num))

        # handle all other transactions outside of coinbase
        for txn in range(1, len(block.extended_transactions)):
            tx = block.extended_transactions[txn].tx
            addr_from = block.extended_transactions[txn].addr_from.hex()
            tx_hash = tx.transaction_hash.hex()
            if tx.fee > 0:
                balances_store[addr_from] -= tx.fee
                if dbg_addr in [addr_from]:
                    print('fee amnt {} Q{} -> Q{} via tx {}'.format(tx.fee, addr_from, address, tx_hash))
            if tx.HasField('transfer'):
                update_balances(balances_store, addr_from, tx.transfer, dbg_addr, tx_hash)
            if tx.HasField('multi_sig_spend'):
                if has_multi_sig_spend_executed(qrl_client, tx.transaction_hash):
                    addr_from = tx.multi_sig_spend.multi_sig_address.hex()
                    update_balances(balances_store, addr_from, tx.multi_sig_spend, dbg_addr, tx_hash)

    logging.info('loaded {} addresses and {} transactions'.format(len(balances_store), len(transaction_store)))

    # audit each block, checking the block header and building a list
    for block_num in range(0, total_blocks):
        block = block_store[block_num]
        if block_num > 0:
            blockPrev = block_store[block_num-1]
            if block.header.hash_header_prev != blockPrev.header.hash_header:
                logging.error('prev block error at {}'.format(block_num))
            if block.header.timestamp_seconds < blockPrev.header.timestamp_seconds:
                logging.error('timestamp error at {}'.format(block_num))
        if block.header.block_number != block_num:
            logging.error('block num error at {}'.format(block_num))
        hashedtransactions = [block.extended_transactions[0].tx.transaction_hash]
        reward = block.header.reward_block
        for txn in range(1, len(block.extended_transactions)):
            reward += block.extended_transactions[txn].tx.fee
            hashedtransactions.append(block.extended_transactions[txn].tx.transaction_hash)
        if block.extended_transactions[0].tx.coinbase.amount != reward:
            logging.error('coinbase error at {}'.format(block_num))
        if block.header.reward_fee + block.header.reward_block != reward:
            logging.error('reward error at {}'.format(block_num))
        merkle_root = merkle_tx_hash(hashedtransactions)
        if block.header.merkle_root != merkle_root:
            logging.error('merkle_root error at {}'.format(block_num))

    for addr in balances_store:
        try:
            balance = audit_address(qrl_client, 'Q'+addr, False)
            if balance != balances_store[addr]:
                logging.error('balance for {} does not match'.format('Q'+addr))
                logging.error('node-reported balance: {}'.format(balance))
                logging.error('calculated balance:    {}'.format(balances_store[addr]))
        except:
            logging.error('could not query addr {}'.format('Q'+addr))
            raise

"""
Main
"""
logging.basicConfig(stream=sys.stdout, level=logging.INFO)

args = define_args()
if not validate_args(args):
    sys.exit()

address = '{}:{}'.format(args.host, args.port)
qrl_client = connect_client(address)
logging.info('Connected to {} '.format(address))

start = time.monotonic()

if args.type == 'address':
    audit_address(qrl_client, args.object)
elif args.type == 'chain':
    audit_chain(qrl_client, args.object)

end = time.monotonic()
elapsed = int(end - start)
logging.info('elapsed time: {} seconds'.format(elapsed))
