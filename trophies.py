import json
import os
import sys
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
import requests as req

api = os.getenv('PRISMA_API_URL')
username = os.getenv('PRISMA_ACCESS_KEY_ID')
password = os.getenv('PRISMA_SECRET_KEY')

if api is None or username is None or password is None:
    print('Missing environment variables')
    sys.exit(1)

# Get current date
current_date = datetime.now()

# Calculate one month ago and six months ago
one_month_ago = current_date - timedelta(days=30)
six_months_ago = current_date - timedelta(days=30 * 6)

# Format the dates as desired
one_month_ago_formatted = one_month_ago.strftime("%Y-%m-%d 00:00:00.000")
six_months_ago_formatted = six_months_ago.strftime("%Y-%m-%d 00:00:00.000")


# ANSI color codes
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    END = '\033[0m'

def color_print(text, color):
    print(color + text + Colors.END)

def authenticate():
    payload = {'username': username, 'password': password}
    headers = {'Content-Type': 'application/json; charset=UTF-8', 'Accept': 'application/json; charset=UTF-8'}
    result = req.post(f"{api}/login", data=json.dumps(payload), headers=headers, timeout=30)
    result.raise_for_status()
    return result.json()['token']


def create_headers(token):
    return {'Content-Type': 'application/json; charset=UTF-8', 'Accept': 'application/json; charset=UTF-8',
            'x-redlock-auth': token}


def make_request(method, endpoint, payload=None):
    token = authenticate()
    headers = create_headers(token)
    if method == "GET":
        result = req.get(f"{api}/{endpoint}", headers=headers, timeout=30)
    else:
        result = req.post(f"{api}/{endpoint}", headers=headers, data=json.dumps(payload), timeout=30)
    result.raise_for_status()
    return result


def get_fixed_percentage(csv_data):
    lines = csv_data.split('\"\\n')
    rows = [line.split(',') for line in lines[1:]]
    total_events = len(rows)
    total_fixed = sum(1 for row in rows if row[6].strip("\\\"") == "Yes")
    return round((total_fixed / total_events) * 100, 0)


def get_cicd_findings():
    payload = {"status": "open", "severities": ["critical", "high", "medium"]}
    result = make_request("POST","bridgecrew/api/v1/pipeline-risks/export", payload)
    percentage_fixed = get_fixed_percentage(result.text)
    color_print("20 percent of Medium/High CI/CD Findings Fixed:{}".format(percentage_fixed), Colors.GREEN)


def get_all_cicd_findings():
    payload = {"status": "open", "severities": ["critical", "high", "medium", "low", "informational"]}
    result = make_request("POST", "bridgecrew/api/v1/pipeline-risks/export", payload)
    percentage_fixed = get_fixed_percentage(result.text)
    print("80% of all risks are prevented in the pipeline:", percentage_fixed, "%")


def get_vcs_scan_findings():
    def process_request(payload):
        result = make_request("POST", "code/api/v2/dashboard/vcs-scan-issues-over-time", payload)
        data = result.json()['data']
        return sum(int(entry['openCount']) for entry in data), sum(int(entry['fixedCount']) for entry in data)

    with ThreadPoolExecutor() as executor:
        payloadX = {"startDate": one_month_ago_formatted, "codeCategories": ["secrets"]}
        payloadY = {"startDate": six_months_ago_formatted, "codeCategories": ["secrets"]}
        futureX = executor.submit(process_request, payloadX)
        futureY = executor.submit(process_request, payloadY)
        total_open_countX, total_fixed_countX = futureX.result()
        total_open_countY, total_fixed_countY = futureY.result()

    percentage_fixedX = round((total_fixed_countX / total_open_countX) * 100, 0)
    percentage_fixedY = round((total_fixed_countY / total_open_countY) * 100, 0)
    result = percentage_fixedY - percentage_fixedX
    print("10% increase in Number of fixed vs opened code security issue:", result, "%")


def get_vcs_scan_secret_findings():
    payload = {"startDate": six_months_ago_formatted, "codeCategories": ["secrets"]}
    result = make_request("POST","code/api/v2/dashboard/vcs-scan-issues-over-time", payload)
    dataY = result.json()

    # Initialize counts
    total_open_count = 0
    total_fixed_count = 0

    # Iterate over data entries
    for entry in dataY['data']:
        total_open_count += int(entry['openCount'])
        total_fixed_count += int(entry['fixedCount'])


    # Calculate the percentage of not fixed events
    percentage_fixed = round((total_fixed_count / total_open_count) * 100, 0)

    # Check if percentage is 50 or more, then print "Passed"
    if percentage_fixed >= 50:
        print("50% reduction of secret exposure: True",percentage_fixed,"%")
    elif percentage_fixed >= 80:
        print("80% reduction of secret exposure: True", percentage_fixed,"%")
    else:
        print("50% reduction of secret exposure: False", percentage_fixed,"%")
        print("80% reduction of secret exposure: False", percentage_fixed,"%")



def get_pipeline_runs_data():
    result = make_request("GET","code/api/v1/development-pipeline/code-review/runs/data", {})
    data = result.json()['data']
    total_events = len(data)
    hard_fail_events = sum(1 for event in data if event["scanStatus"] == "HARD_FAIL")
    percentage_fixed = round((hard_fail_events / total_events) * 100, 0)
    print("80% of High code issues blocked:", percentage_fixed, "%")


if __name__ == '__main__':
    print('Get CAS Metrics -  0.0.1')
    get_cicd_findings()
    get_all_cicd_findings()
    get_vcs_scan_findings()
    get_vcs_scan_secret_findings()
    get_pipeline_runs_data()
    print('Done')
