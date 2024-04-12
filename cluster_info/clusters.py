import json
import os
import sys
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
import requests as req


# ANSI color codes
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    END = '\033[0m'

def color_print(text, color, file=None):
    print(color + text + Colors.END, file=file)

api = os.getenv('PRISMA_API_URL')
username = os.getenv('PRISMA_ACCESS_KEY_ID')
password = os.getenv('PRISMA_SECRET_KEY')
console_address = os.getenv('PRISMA_CONSOLE_ADDRESS')

if api is None:
    color_print("Missing PRISMA_API_URL environment variable",Colors.RED, file=sys.stderr)
if username is None:
    color_print("Missing PRISMA_ACCESS_KEY_ID environment variable", Colors.RED, file=sys.stderr)
if password is None:
    color_print("Missing PRISMA_SECRET_KEY environment variable", Colors.RED, file=sys.stderr)
if console_address is None:
    color_print("Missing PRISMA_CONSOLE ADDRESS environment variable", Colors.RED, file=sys.stderr)


if api is None or username is None or password is None or console_address is None:
    sys.exit(1)


def authenticate():
    payload = {'username': username, 'password': password}
    headers = {'Content-Type': 'application/json; charset=UTF-8', 'Accept': 'application/json; charset=UTF-8'}
    result = req.post(f"{api}/login", data=json.dumps(payload), headers=headers, timeout=30)
    result.raise_for_status()
    return result.json()['token']


def create_headers(token):
    return {'Content-Type': 'application/json; charset=UTF-8', 'Accept': 'application/json; charset=UTF-8',
            'x-redlock-auth': token}


def make_request(endpoint):
    token = authenticate()
    headers = create_headers(token)
    result = req.get(f"{console_address}/{endpoint}", headers=headers, timeout=30)
    result.raise_for_status()
    return result

def write_cluster_info_to_json(cluster_info):
    output_data = []
    for cluster in cluster_info:
        name = cluster.get('name', '')
        cloud_provider = cluster.get('cloudProivder', '')  # Note the typo correction
        output_data.append({'name': name, 'cloudProivder': cloud_provider})  # Note the typo correction
    
    try:
        with open('output.json', 'w') as outfile:
            json.dump(output_data, outfile, indent=4)
        color_print("Success: JSON data has been written to output.json", Colors.GREEN)
    except Exception as e:
        print(f"Error: Unable to write JSON data to output.json - {e}")
    
    # Count the total number of clusters based on the 'name' key
    total_clusters = sum(1 for cluster in cluster_info if cluster.get('name'))
    color_print(f"Total number of clusters: {total_clusters}", Colors.YELLOW)

def get_cluster_info():
    result = make_request("api/v1/radar/container/clusters?project=Central+Console")
    cluster_info = json.loads(result.text)
    write_cluster_info_to_json(cluster_info)
    

if __name__ == '__main__':
    color_print("Get Cluster Info -  v1.0 - Initiated", Colors.END)
    get_cluster_info()
    color_print("Get Cluster Info -  v1.0 - Completed", Colors.END)