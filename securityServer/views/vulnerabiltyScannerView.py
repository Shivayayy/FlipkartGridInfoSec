import subprocess
import re
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from pymongo import MongoClient
import os
import logging

logger = logging.getLogger(__name__)

# MongoDB connection
mongodb_uri = os.getenv('MONGODB_URI')
if mongodb_uri is None:
    raise ValueError("MONGODB_URI environment variable not set")
client = MongoClient(mongodb_uri)
db = client.get_default_database()
api_endpoints_collection = db['apiEndpointInventory']
scan_results_collection = db['vulnerabilityScanReports']

# Base URL for building full API URLs
base_url = 'https://onlineshop-psi-seven.vercel.app'


def fetch_unique_endpoints():
    """Fetches unique endpoints from the database."""
    return api_endpoints_collection.distinct('path')


def run_vulnapi_scan(url):
    """Runs the vulnAPI scan using Docker and returns the result."""
    try:
        result = subprocess.run(
            ["docker", "run", "--rm", "cerberauth/vulnapi", "scan", "curl", url],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=300
        )
        if result.returncode != 0:
            logger.error(f"Error running vulnAPI scan: {result.stderr}")
            return None
        return result.stdout
    except subprocess.TimeoutExpired:
        logger.error("VulnAPI scan timed out")
        return None
    except Exception as e:
        logger.error(f"An error occurred while running vulnAPI scan: {e}")
        return None


def strip_ansi_codes(text):
    """Removes ANSI escape sequences from a string."""
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)


def process_vulnapi_output(output):
    if not output:
        return None

    # Strip out any ANSI escape sequences
    output = strip_ansi_codes(output)

    # Use regex to locate the vulnerability table
    table_start = re.search(
        r'\|\s+OPERATION\s+\|\s+RISK LEVEL\s+\|\s+CVSS 4\.0 SCORE\s+\|\s+OWASP\s+\|\s+VULNERABILITY\s+\|', output)

    if not table_start:
        logger.error("Vulnerability table not found in VulnAPI output")
        return None

    # Extract the table lines from the output
    table_data = output[table_start.start():]

    # Split lines and extract headers and rows
    lines = table_data.splitlines()
    headers = [header.strip() for header in lines[0].split('|') if header.strip()]
    data = []

    for line in lines[2:]:
        if line.strip() and not line.startswith('+'):
            values = [value.strip() for value in line.split('|') if value.strip()]
            if len(values) == len(headers):
                data.append(dict(zip(headers, values)))
            else:
                # If a row is incomplete, try to append to the last element of the previous row
                if data:
                    data[-1][headers[-1]] += ' ' + ' '.join(values)

    return data


@csrf_exempt
def scan_api_view(request):
    """Django view to trigger the scan and return the results."""
    try:
        if request.method == 'GET':
            # Handle GET request to trigger the scan
            unique_endpoints = fetch_unique_endpoints()
            results = []
            for path in unique_endpoints:
                full_url = f'{base_url}{path.rstrip("/")}/'
                scan_result = run_vulnapi_scan(full_url)
                if scan_result is not None:
                    processed_result = process_vulnapi_output(scan_result)
                    if processed_result is not None:
                        result = {
                            "url": full_url,
                            "vulnerabilities": processed_result
                        }
                        results.append(result)
                        # Store the result in the database
                        scan_results_collection.insert_one(result)

            if not results:
                return JsonResponse({"error": "No valid scan results obtained"}, status=500)

            return JsonResponse({
                "status": "Ok",
                "message": f"Scanned {len(results)} endpoints",
                "results": results
            })
        else:
            return JsonResponse({"error": "This endpoint only accepts GET requests"}, status=405)
    except Exception as e:
        logger.error(f"An unexpected error occurred in scan_api_view: {str(e)}")
        return JsonResponse({"error": "An unexpected error occurred"}, status=500)
