import json
import time
import requests
from web3 import Web3
from web3.middleware import geth_poa_middleware
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)
#all code here

from datetime import datetime

from influxdb_client import InfluxDBClient, Point, WritePrecision, WriteOptions
from influxdb_client.client.write_api import SYNCHRONOUS



def connect_to_influxdb(url, token, org):

    write_api = None
    client = None
    try:
        client = InfluxDBClient(url=url, token=token)
        write_api = client.write_api(write_options=SYNCHRONOUS)
        print("Connected to InfluxDB")

    except Exception as e:
        print(f"An error occurred while using InfluxDB: {e}")
        return 0
    
    return write_api, client




def get_last_block_influxdb(client,url,token,org,bucket):

    
    client = InfluxDBClient(url=url, token=token, org = org)
    query_api = client.query_api()

    print("Bucket name:",bucket)

    query = f'''
        from(bucket: "{bucket}")
            |> range(start:-30d)
            |> filter(fn:(r) => r._measurement == "block_info")
            |> filter(fn:(r) => r._field == "block_number")
            |> last()

        '''
    result = query_api.query(query)

    if not result:
        print("No last block found in the database")
        return 0

    if result:
        for table in result:
            for record in table.records:
                last_block_number = record.get_value()
                print(f"Last block number: {last_block_number}")

        return last_block_number                  
    else:
        print("No last block number found in the database")
        return 0 
        
    
    

def get_timestamp(w3,block_number):

    block = w3.eth.get_block(block_number)
    block_datetime = datetime.utcfromtimestamp(block.timestamp)

    formatted_datetime = block_datetime.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] + '+00:00' 

    return formatted_datetime



def trace_block_internal_transaction(w3, block_number):

    block = w3.eth.get_block(block_number)

    if (not block.transactions or len(block.transactions) == 0):

        return 0 

    transaction_trace = []
    internal_transaction_count = 0

    for tx_hash in block.transactions:
        #print("0x"+ tx_hash.hex())
        try:
            payload = {
                "jsonrpc": "2.0",
                "method": "debug_traceTransaction",
                "params": [tx_hash.hex(),{"reexec":99999}],
                "id": int(time.time())
            }

            headers = {"Content-Type": "application/json"}

            #response = w3.manager.request_blocking(method='debug_traceTransaction', params=["0x"+ tx_hash.hex(),{}])
            response = requests.post('http://localhost:8545', json=payload, headers = headers)

            if 'error' in response:
                raise Exception(response['Error']['Message'])
            
            #print(response)
            response_data = response.json()
            
            #print(json.loads(response_data))
            #print(response_data)
            #print(json.loads(response.text))
            trace_result = response_data.get('result')
            #print(trace_result)

            #print(len(transaction_trace))
            transaction_trace.append(trace_result)
            
    
        except Exception as e:
            print(f"An error occurred: di internal transaction {e}")

    #print(transaction_trace)


    for trace in transaction_trace:
        if 'structLogs' in trace:
            # Check if any structLog has a "depth" greater than 0, indicating an internal call
            if any(log['depth'] > 0 for log in trace['structLogs']):
                internal_transaction_count += 1

    #print(internal_transaction_count)

    if internal_transaction_count is None or internal_transaction_count == 0:

        internal_transaction_count = 0
        return internal_transaction_count
    else:

        return internal_transaction_count


def get_total_transaction_fee(w3,block_number):

    try:
        block = w3.eth.get_block(block_number)

        if not block:
            print(f"Block {block_number} not found.")
            return 0 
            
        total_transaction_fee = 0

        if block.transactions and len(block.transactions) > 0:
            for tx_hash in block.transactions:
                tx = w3.eth.get_transaction(tx_hash)

                if not tx:
                    print(f"Transaction not found {tx_hash}.")
                    continue

                gas_price = int(tx.gasPrice)
                gas = int(tx.gas)

                if gas_price is None or gas is None:
                    print(f"Gas price or gas not found for transaction {tx_hash}.")
                    continue

                transaction_fee = w3.from_wei(gas * gas_price, 'ether')
                total_transaction_fee += transaction_fee


        return total_transaction_fee



    except Exception as e:
        print(f"An error occurred: di total transaction {e}")
        return 0 

def get_block_transaction(w3,block_number):

    block = w3.eth.get_block(block_number, full_transactions=True)

    transaction = [
        tx if isinstance(tx, str) else tx.hash.hex()
        
        for tx in block.transactions
    ]

    if transaction:
        return  transaction
    else:
        return None

def get_block_miner(w3, block_hash):
    try:
        payload = {
            "jsonrpc": "2.0",
            "method": "clique_getSigner",
            "params": [block_hash,True],
            "id": int(time.time())
        }

        response = w3.manager.request_blocking(method='clique_getSigner', params=[block_hash])
        return response

    except Exception as e:
        print(f"An error occurred: di miner {e}")
        # Use default value in case of error
        return '0x29e7152d0456258fa4babb7a3f37b8a0347684eb'

def get_all_data_block(w3,client,url, token, org,bucket):

    latest_block_number = w3.eth.get_block_number()
    last_block_number = get_last_block_influxdb(client,url, token, org, bucket)

    for block_number in range(last_block_number + 1, 9000+1):
        try:
            block_desc = w3.eth.get_block(block_number)
            block_transaction = w3.eth.get_block_transaction_count(block_number)

            block_hash = block_desc.hash.hex()
            block_hash_with_prefix = "0x" + block_hash

            response_miner = get_block_miner(w3, block_hash)
            transaction_fee = get_total_transaction_fee(w3, block_number)

            internal_transaction_count = trace_block_internal_transaction(w3, block_number)

            block_reward = get_total_transaction_fee(w3, block_number) + 0 
            timestamp_block = get_timestamp(w3, block_number)
            
            #block_number = w3.eth.get_block(block_desc)
            
            parent_hash = block_desc.parentHash.hex()
            nonce = int.from_bytes(block_desc.nonce, byteorder='big')
            sha3Uncles = block_desc.sha3Uncles.hex()
            miner = response_miner
            difficulty = float(block_desc.difficulty)
            total_difficulty = float(block_desc.totalDifficulty)
            size = int(block_desc.size)
            gas_limit = int(block_desc.gasLimit)
            gas_used = int(block_desc.gasUsed)
            transaction = get_block_transaction(w3,block_number)

            extra_data = block_desc.proofOfAuthorityData.hex() if 'proofOfAuthorityData' in block_desc else None
            
            print(f"block number: {block_number}")
            
            print(f"Block Hash :{block_hash}")
            
            print(f"Internal Transaction: {internal_transaction_count}")

            '''data_point = {
                "measurement": "block_info",
                "fields":{
                    "block_number": block_number,
                    "block_hash": "0x"+block_hash,
                    "parent_hash": "0x"+parent_hash,
                    "nonce": nonce,
                    "sha3_uncles": "0x"+sha3Uncles,
                    "transaction": str(transaction),
                    "miner":miner,
                    "difficulty": difficulty,
                    "total_difficulty": total_difficulty,
                    "size": size,
                    "extra_data":"0x"+extra_data,
                    "gas_limit": gas_limit,
                    "gas_used":gas_used,
                    "timestamp": timestamp_block,
                    "transaction_number": block_transaction,
                    "transaction_fee": int(transaction_fee),
                    "internal_transaction_count":internal_transaction_count,
                    "block_reward": int(block_reward)

                }
              }'''



            point = Point("block_info") \
                .field("block_number", block_number) \
                .field("block_hash", "0x" + block_hash) \
                .field("parent_hash", "0x" + parent_hash) \
                .field("nounce", nonce) \
                .field("sha3_uncles", "0x" + sha3Uncles) \
                .field("transaction", str(transaction)) \
                .field("miner", miner) \
                .field("difficulty", difficulty) \
                .field("total_difficulty", total_difficulty) \
                .field("size", size) \
                .field("extra_data", "0x" + extra_data) \
                .field("gas_limit", gas_limit) \
                .field("gas_used", gas_used) \
                .field("timestamp", timestamp_block) \
                .field("transaction_number", block_transaction) \
                .field("transaction_fee", int(transaction_fee)) \
                .field("internal_transaction_count", internal_transaction_count) \
                .field("block_reward", int(block_reward)) 
                


            print("-----------------------------------------------------------------")

            write_options = WriteOptions(batch_size=500, flush_interval=10_000)
            write_api = client.write_api(write_options=write_options)

            write_api.write(bucket=bucket, org=org, record=point)
            #client.write_points([data_point],time_precision="ms")

            #point = Point(data_point["measurement"])

            '''for field, value in data_point["fields"].items():
                point = point.field(field, value)

                point = point.time(data_point["fields"]["timestamp"], WritePrecision.MS)
                write_api.write(bucket=bucket, org=org, record=point)'''


        except Exception as e:
            logger.error(f"Error occurred while fetching block {block_number}: {e}")
            raise



    print("Fetch to latest block successfully!")
    #write_api.close()
    return


url= "http://localhost:8086"
token = "fs4RG_hKp6V2s5WCIBwY4XKx7lWiUad27rQgToMq-QcHLzH2aEMDxJbpUPZesL0a20SDeyEIufHYmI0ZugbdVw=="
org = "my-org"
bucket = "Block_test_14_block"


write_api, client = connect_to_influxdb(url, token, org)

url_local='http://localhost:8545'
w3 = Web3(Web3.HTTPProvider(url_local))
w3.middleware_onion.inject(geth_poa_middleware, layer=0)
#connect_eth_with_last_block_number(w3)

get_all_data_block(w3,client, url, token, org, bucket)
