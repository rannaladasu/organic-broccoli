import json
import os
import sys
import traceback
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
    log_debug(text)

def log_debug(message, response=None):
    """Logs debug information with optional API response details."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {message}\n"

    if DEEP_DEBUG_MODE and response is not None:
        try:
            response_data = json.dumps(response.json(), indent=4)
        except Exception:
            response_data = response.text  # Fallback if response is not JSON

        log_entry += f"API Response:\n{response_data}\n\n"

    with open("debug_log.txt", "a") as log_file:
        log_file.write(log_entry)

# Debug mode activation
DEBUG_MODE = os.getenv("DEBUG_MODE") == "1" or "--debug" in sys.argv
DEEP_DEBUG_MODE = os.getenv("DEEP_DEBUG_MODE") == "1" or "--deep-debug" in sys.argv

if DEBUG_MODE or DEEP_DEBUG_MODE:
    with open("debug_log.txt", "w") as log_file:  # Clear log at start
        log_file.write("DEBUG LOG STARTED\n")

api = os.getenv('PRISMA_API_URL')
username = os.getenv('PRISMA_ACCESS_KEY_ID')
password = os.getenv('PRISMA_SECRET_KEY')

if api is None:
    color_print("Missing PRISMA_API_URL environment variable", Colors.RED, file=sys.stderr)
if username is None:
    color_print("Missing PRISMA_ACCESS_KEY_ID environment variable", Colors.RED, file=sys.stderr)
if password is None:
    color_print("Missing PRISMA_SECRET_KEY environment variable", Colors.RED, file=sys.stderr)

if api is None or username is None or password is None:
    sys.exit(1)

# Get current date
current_date = datetime.now()
one_month_ago = current_date - timedelta(days=30)
six_months_ago = current_date - timedelta(days=30 * 6)

one_month_ago_formatted = one_month_ago.strftime("%Y-%m-%d 00:00:00.000")
six_months_ago_formatted = six_months_ago.strftime("%Y-%m-%d 00:00:00.000")


def authenticate():
    """Handles authentication and token retrieval."""
    log_debug("Authenticating with Prisma API...")
    payload = {'username': username, 'password': password}
    headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
    try:
        result = req.post(f"{api}/login", json=payload, headers=headers, timeout=30)
        result.raise_for_status()
        log_debug("Authentication successful.", result)
        return result.json().get('token')
    except Exception as e:
        log_debug(f"Authentication failed: {e}")
        sys.exit(1)


def create_headers(token):
    return {'Content-Type': 'application/json', 'Accept': 'application/json', 'x-redlock-auth': token}


def make_request(method, endpoint, payload=None):
    """Handles API requests with detailed debugging."""
    log_debug(f"Making {method} request to {api}/{endpoint}")
    token = authenticate()
    headers = create_headers(token)
    try:
        if method == "GET":
            result = req.get(f"{api}/{endpoint}", headers=headers, timeout=30)
        else:
            result = req.post(f"{api}/{endpoint}", headers=headers, json=payload, timeout=30)
        result.raise_for_status()
        log_debug(f"Response from {endpoint}: {result.status_code}", result)
        return result
    except Exception as e:
        log_debug(f"Error in {method} request to {endpoint}: {traceback.format_exc()}")
        return None


def get_fixed_percentage(csv_data):
    """Calculates the percentage of fixed issues from CSV data."""
    try:
        lines = csv_data.split('\"\\n')
        rows = [line.split(',') for line in lines[1:]]
        total_events = len(rows)
        total_fixed = sum(1 for row in rows if row[6].strip("\\\"") == "Yes")
        percentage = round((total_fixed / total_events) * 100, 0)
        log_debug(f"Fixed percentage calculated: {percentage}%")
        return percentage
    except Exception as e:
        log_debug(f"Error calculating fixed percentage: {traceback.format_exc()}")
        return 0


def get_cicd_findings():
    """Retrieves CI/CD findings and calculates fixed percentage."""
    log_debug("Fetching CI/CD findings...")
    payload = {"status": "open", "severities": ["critical", "high", "medium"]}
    result = make_request("POST", "bridgecrew/api/v1/pipeline-risks/export", payload)
    if result:
        percentage_fixed = get_fixed_percentage(result.text)
        status = "True" if percentage_fixed >= 20 else "False"
        color_print(f"20% of Medium/High CI/CD Findings Fixed: {status} - {percentage_fixed}%", Colors.GREEN if status == "True" else Colors.RED)


def get_all_cicd_findings():
    """Fetches all CI/CD findings and verifies risk prevention."""
    log_debug("Fetching all CI/CD findings...")
    payload = {"status": "open", "severities": ["critical", "high", "medium", "low", "informational"]}
    result = make_request("POST", "bridgecrew/api/v1/pipeline-risks/export", payload)
    if result:
        percentage_fixed = get_fixed_percentage(result.text)
        status = "True" if percentage_fixed >= 80 else "False"
        color_print(f"80% of all risks are prevented in the pipeline: {status} - {percentage_fixed}%", Colors.GREEN if status == "True" else Colors.RED)


def get_vcs_scan_findings():
    """Analyzes VCS scan findings for security issues."""
    def process_request(payload):
        result = make_request("POST", "code/api/v2/dashboard/vcs-scan-issues-over-time", payload)
        if result:
            data = result.json().get('data', [])
            return sum(int(entry['openCount']) for entry in data), sum(int(entry['fixedCount']) for entry in data)
        return 0, 0

    log_debug("Fetching VCS scan findings...")
    with ThreadPoolExecutor() as executor:
        payloadX = {"startDate": one_month_ago_formatted, "codeCategories": ["secrets"]}
        payloadY = {"startDate": six_months_ago_formatted, "codeCategories": ["secrets"]}
        futureX = executor.submit(process_request, payloadX)
        futureY = executor.submit(process_request, payloadY)
        total_open_countX, total_fixed_countX = futureX.result()
        total_open_countY, total_fixed_countY = futureY.result()

    percentage_fixedX = round((total_fixed_countX / total_open_countX) * 100, 0) if total_open_countX else 0
    percentage_fixedY = round((total_fixed_countY / total_open_countY) * 100, 0) if total_open_countY else 0
    result = percentage_fixedY - percentage_fixedX
    status = "True" if result >= 10 else "False"
    color_print(f"10% increase in Number of fixed vs opened code security issue: {status} - {result}%", Colors.GREEN if status == "True" else Colors.RED)


if __name__ == '__main__':
    color_print("Get CAS Metrics - v1.0 - Initiated", Colors.GREEN)
    get_cicd_findings()
    get_all_cicd_findings()
    get_vcs_scan_findings()
    color_print("Get CAS Metrics - v1.0 - Completed", Colors.GREEN)
