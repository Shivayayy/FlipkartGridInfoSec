# views.py

import json
import os
from collections import Counter
import logging
from datetime import datetime
from pymongo import MongoClient
from bson import json_util
from dotenv import load_dotenv
from bson import ObjectId
from django.http import JsonResponse, HttpResponseNotFound
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.http import  HttpResponseBadRequest
import json
from pytz import timezone
from datetime import timedelta, datetime


# Set up logging
logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()

# Get MongoDB URI from environment variable
mongodb_uri = os.getenv('MONGODB_URI')
if mongodb_uri is None:
    raise ValueError("MONGODB_URI environment variable not set")

# Connect to MongoDB
client = MongoClient(mongodb_uri)
db = client.get_default_database()

# Initialize collections
api_endpoints_collection = db['apiEndpointInventory']
api_req_inventory_collection = db['apiReqInventory']
owasp_req_scanner_collection = db['owaspReqScanner']
spider_scan_reports_collection = db['spiderScanReports']


import logging
from django.http import JsonResponse
from datetime import datetime
import pytz  # Import pytz for timezone handling

# Configure logging settings
logging.basicConfig(level=logging.DEBUG)  # Adjust logging level as needed
logger = logging.getLogger(__name__)

from django.http import JsonResponse
from datetime import datetime
import pytz
from collections import defaultdict

def get_api_reports(request):
    # Define the IST timezone
    ist = pytz.timezone('Asia/Kolkata')

    # Fetch scan reports from your data source
    reports = spider_scan_reports_collection.find()  # Adjust this query to fit your actual database interaction

    # Initialize default dictionaries for overall counts
    overall_cweid_counts = defaultdict(int)
    overall_owasp_tag_counts = defaultdict(int)

    # Initialize a list to collect data
    formatted_data = []

    for report in reports:
        tickets = report.get('tickets', [])
        utc_timestamp = report['timestamp']

        # Convert UTC timestamp to IST
        if isinstance(utc_timestamp, datetime):
            utc_timestamp = utc_timestamp.replace(tzinfo=pytz.utc)  # Ensure the datetime is timezone-aware
        ist_timestamp = utc_timestamp.astimezone(ist)
        ist_timestamp_str = ist_timestamp.strftime('%Y-%m-%d %I:%M:%S %p')  # Format: 2024-08-18 07:12:40 PM

        # Calculate the number of endpoints and total number of alerts
        endpoints = list(report['report'].keys())
        num_endpoints = len(endpoints)
        total_alerts = sum(len(alert_data['alerts']) for alert_data in report['report'].values())

        # Initialize dictionaries for per-scan counts
        cweid_counts = defaultdict(int)
        owasp_tag_counts = defaultdict(int)

        # Build the report data and count occurrences
        formatted_report = []
        for endpoint, alert_data in report['report'].items():
            for alert in alert_data['alerts']:
                cweid = alert.get('cweid')
                if cweid and int(cweid) >= 0:
                    cweid_counts[cweid] += 1
                    overall_cweid_counts[cweid] += 1  # Update overall counts

                # Check and count OWASP tags
                tags = alert.get('tags', {})
                for tag_key in tags:
                    if tag_key.startswith('OWASP_2021_'):
                        tag_value = tag_key[-3:]  # Get the last three characters
                        owasp_tag_counts[tag_value] += 1
                        overall_owasp_tag_counts[tag_value] += 1  # Update overall counts

            formatted_report.append({
                "endpoint": endpoint,
                "alerts": alert_data['alerts']
            })

        # Append the data to formatted_data
        formatted_data.append({
            "id": str(report['_id']),
            "timestamp": ist_timestamp_str,
            "numEndpoints": num_endpoints,
            "totalAlerts": total_alerts,
            "cweidCounts": dict(cweid_counts),  # Per-scan CWE ID counts
            "owaspTagCounts": dict(owasp_tag_counts),  # Per-scan OWASP tag counts
            "report": formatted_report,
            "tickets":tickets,
        })

    # Convert overall counts to arrays
    overall_cweid_array = [{"cweid": cweid, "count": count} for cweid, count in overall_cweid_counts.items()]
    overall_owasp_tag_array = [{"tag": tag, "count": count} for tag, count in overall_owasp_tag_counts.items()]

    # Include both per-scan and overall arrays in the response
    response_data = {
        "reports": formatted_data,
        "overallCweidArray": overall_cweid_array,
        "overallOwaspTagArray": overall_owasp_tag_array
    }

    return JsonResponse(response_data, safe=False, json_dumps_params={'indent': 2})


def api_data_view(request):
    """Fetch unique API endpoints, calculate security metrics, and return as JSON."""
    try:
        # Get all unique API endpoints with relevant fields
        api_endpoints = list(api_endpoints_collection.find({}, {'_id': 0, 'endpoint': 1, 'method': 1, 'path': 1, 'average_risk_score': 1, 'risk_factor': 1,'status':1}))

        # Get total number of APIs
        total_apis = len(api_endpoints)


        # Determine vulnerable APIs
        vulnerable_apis = [api for api in api_endpoints if api.get('risk_factor') not in ['Basic', 'Low']]
        num_vulnerable_apis = len(vulnerable_apis)

        # Secure APIs count
        secure_apis = total_apis - num_vulnerable_apis

        # Prepare the API endpoints data
        api_endpoints_data = []
        for endpoint in api_endpoints:
            risk = "Secure"
            if endpoint.get('average_risk_score', 0) >= 3:
                risk = "High"
            elif endpoint.get('average_risk_score', 0) >= 2:
                risk = "Medium"
            elif endpoint.get('average_risk_score', 0) >= 1:
                risk = "Low"

            api_endpoints_data.append({
                "endpoint": endpoint.get('path'),
                "method": endpoint.get('method'),
                "headers": ["Content-Type"],  # Customize this if needed
                "risk": risk,
                "status":endpoint.get('status'),
                "first_seen": endpoint.get('first_seen', datetime.utcnow()).isoformat(),
                "last_seen": endpoint.get('last_seen', datetime.utcnow()).isoformat(),
                "name": endpoint.get('endpoint')  # Add the name of the API if necessary
            })

        # Get OWASP results
        owasp_results = list(owasp_req_scanner_collection.find({}))

        # Count occurrences of each OWASP_id
        owasp_id_count = {}
        for result in owasp_results:
            owasp_id = result.get('OWASP_id')
            if owasp_id:
                if owasp_id in owasp_id_count:
                    owasp_id_count[owasp_id] += 1
                else:
                    owasp_id_count[owasp_id] = 1

        owasp_id_count_array = [{"owasp_id": owasp_id, "count": count} for owasp_id, count in owasp_id_count.items()]
        # Prepare the final data structure
        api_data = {
            "totalAPI": total_apis,
            "vulnerableAPI": num_vulnerable_apis,
            "secureAPI": secure_apis,
            "vulnerableEndpoints": vulnerable_apis,
            "apiEndpoints": api_endpoints_data,
            "owasp_id_counts": owasp_id_count_array  # Add OWASP ID counts to the response
        }

        # Use json_util to handle MongoDB date objects, then load as Python dict
        return JsonResponse(json.loads(json_util.dumps(api_data)), safe=False)
    except Exception as e:
        logger.error(f"An error occurred while fetching API data: {e}")
        return JsonResponse({"error": "Failed to fetch API data"}, status=500)

def unique_endpoints_view(request):
    """Fetch unique endpoints and return them as JSON."""
    try:
        # Fetch unique endpoints (paths) directly in the view
        unique_endpoints = api_endpoints_collection.distinct('path')
        return JsonResponse(unique_endpoints, safe=False)
    except Exception as e:
        logger.error(f"An error occurred while fetching unique endpoints: {e}")
        return JsonResponse({"error": "Failed to fetch unique endpoints"}, status=500)


from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.http import JsonResponse, HttpResponseNotFound
from pymongo import MongoClient
import json
import logging
import os
import re
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Set up logging
logger = logging.getLogger(__name__)

# Load MongoDB URI from environment variable
mongodb_uri = os.getenv('MONGODB_URI')
if mongodb_uri is None:
    raise ValueError("MONGODB_URI environment variable not set")

# Initialize MongoDB client and collections
client = MongoClient(mongodb_uri)
db = client.get_default_database()


@csrf_exempt
@require_http_methods(["POST"])
def endpoint_info(request):
    """Fetch detailed information for a specific API endpoint."""
    try:
        # Extract the endpoint path from the request body
        body = json.loads(request.body)
        endpoint_path = body.get('endpoint')

        # Validate endpoint_path
        if not endpoint_path:
            return JsonResponse({"error": "Endpoint not specified in request body"}, status=400)

        # Normalize endpoint path
        normalized_endpoint_path = endpoint_path if endpoint_path.endswith('/') else endpoint_path + '/'
        normalized_endpoint_path_no_slash = normalized_endpoint_path.rstrip('/')

        # Find endpoint in apiEndpointInventory (both with and without trailing slash)
        endpoint_data = api_endpoints_collection.find_one({
            '$or': [
                {'path': normalized_endpoint_path},
                {'path': normalized_endpoint_path_no_slash}
            ]
        })

        if not endpoint_data:
            return HttpResponseNotFound("Endpoint not found")

        # Convert ObjectId to string
        if '_id' in endpoint_data:
            endpoint_data['_id'] = str(endpoint_data['_id'])

        # Find request data in apiReqInventory (both with and without trailing slash)
        requests = list(api_req_inventory_collection.find({
            '$or': [
                {'path': normalized_endpoint_path},
                {'path': normalized_endpoint_path_no_slash}
            ]
        }))

        # Convert ObjectId to string for each request
        for req in requests:
            if '_id' in req:
                req['_id'] = str(req['_id'])

        # Find OWASP scanner results (both with and without trailing slash)
        owasp_results = list(owasp_req_scanner_collection.find({
            '$or': [
                {'api_endpoint': normalized_endpoint_path},
                {'api_endpoint': normalized_endpoint_path_no_slash}
            ]
        }))

        # Convert ObjectId to string for each OWASP result
        for result in owasp_results:
            if '_id' in result:
                result['_id'] = str(result['_id'])

        # Summarize OWASP results
        def summarize_owasp_results(results):
            owasp_ids = [result.get('OWASP_id') for result in results]
            return dict(Counter(owasp_ids))

        owasp_summary = summarize_owasp_results(owasp_results)

        # Find spider scan reports
        spider_reports = list(spider_scan_reports_collection.find({
            'report': {'$exists': True}
        }))

        relevant_reports = []
        for report in spider_reports:
            report_content = report.get('report', {})
            for url, data in report_content.items():
                if normalized_endpoint_path in url or normalized_endpoint_path_no_slash in url:
                    # Convert ObjectId to string
                    report_id = str(report['_id'])
                    timestamp = report.get('timestamp')

                    # Create a new object with only the relevant information
                    relevant_report = {
                        '_id': report_id,
                        'timestamp': timestamp,
                        'report': {
                            url: data
                        }
                    }
                    relevant_reports.append(relevant_report)
                    break  # We found a match, so we can stop looking in this report

        # Compile the response
        owasp_tag_list = [{"id": tag, "count": count} for tag, count in owasp_summary.items()]
        response_data = {
            'endpoint_info': endpoint_data,
            'requests': requests,
            'owasp_results': owasp_results,
            'owasp_summary': owasp_tag_list,  # Add the summary here
            'spider_scan_reports': relevant_reports
        }

        return JsonResponse(response_data, safe=False)
    except Exception as e:
        logger.error(f"An error occurred while fetching endpoint information: {e}")
        return JsonResponse({"error": "Failed to fetch endpoint information"}, status=500)


from django.http import JsonResponse
from django.views import View
from pymongo import MongoClient
import os
from dotenv import load_dotenv
import logging
from bson.json_util import dumps

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()

# Initialize MongoDB client and collection using environment variables
mongodb_uri = os.getenv('MONGODB_URI')
if mongodb_uri is None:
    raise ValueError("MONGODB_URI environment variable not set")

try:
    client = MongoClient(mongodb_uri)
    db = client.get_default_database()
    scan_reports_collection = db['BearerScanReports']
except Exception as e:
    logger.error(f"Failed to connect to MongoDB: {e}")
    raise

from bson import ObjectId
from bson.json_util import dumps
import json
from collections import defaultdict
from django.http import JsonResponse
from django.views import View
import logging

logger = logging.getLogger(__name__)

class BearerScanReportView(View):
    def get(self, request, *args, **kwargs):
        try:
            # Fetch all documents from the BearerScanReports collection
            scan_reports = scan_reports_collection.find()

            # Initialize a list to store reformatted data and a dictionary for CWE counts
            formatted_data = []
            cwe_counts = defaultdict(int)  # Dictionary to count occurrences of each CWE ID

            # Process each report
            for report in scan_reports:
                if 'scan_data' not in report:
                    continue

                report_data = {
                    '_id': str(report['_id']),  # Include MongoDB _id
                    'timestamp': report.get('timestamp'),  # Include timestamp if it exists
                    'files': []  # To store findings categorized by filename
                }

                scan_data = report['scan_data']
                for severity, findings in scan_data.items():
                    for finding in findings:
                        full_filename = finding.get('full_filename', 'Unknown Filename')

                        # Add the severity tag to the finding
                        finding['tag'] = severity

                        # Update CWE counts
                        cwe_ids = finding.get('cwe_ids', [])
                        for cwe_id in cwe_ids:
                            cwe_counts[cwe_id] += 1

                        # Check if this file is already in the files list
                        file_report = next((item for item in report_data['files'] if item['filename'] == full_filename), None)

                        if file_report:
                            # Append the finding to the existing entry
                            file_report['findings'].append(finding)
                        else:
                            # Create a new entry for this file
                            report_data['files'].append({
                                'filename': full_filename,
                                'findings': [finding]
                            })

                # Add the processed report to the formatted data list
                formatted_data.append(report_data)

            cwe_counts_array = [{'cwe_id': cwe_id, 'count': count} for cwe_id, count in cwe_counts.items()]
            # Convert the formatted_data dictionary to JSON
            formatted_data_json = dumps({
                'reports': formatted_data,  # This is now a list of dictionaries
                'cwe_counts': cwe_counts_array  # Convert defaultdict to regular dict for JSON serialization
            })  # bson.json_util.dumps handles ObjectId serialization

            # Return the JSON response
            return JsonResponse(json.loads(formatted_data_json), safe=False)

        except Exception as e:
            logger.error(f"Failed to fetch scan reports: {e}")
            return JsonResponse({"error": "Failed to fetch scan reports.", "details": str(e)}, status=500)




from bson import ObjectId
from bson.json_util import dumps
import json
from collections import defaultdict
from django.http import JsonResponse
from django.views import View
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class StaticSpecific(View):
    def get(self, request, *args, **kwargs):
        report_id = request.GET.get('report_id')
        if not report_id:
            return JsonResponse({"error": "report_id parameter is required."}, status=400)

        try:
            # Convert report_id to ObjectId if it is a valid ObjectId string
            try:
                report_id = ObjectId(report_id)
            except Exception as e:
                logger.error(f"Invalid ObjectId format: {e}")
                return JsonResponse({"error": "Invalid report_id format."}, status=400)

            # Fetch the specific report by report_id
            report = scan_reports_collection.find_one({"_id": report_id})

            if not report:
                return JsonResponse({"error": "Report not found."}, status=404)

            # Initialize a list to store reformatted data and a dictionary for CWE counts
            formatted_data = []
            cwe_counts = defaultdict(int)  # Dictionary to count occurrences of each CWE ID

            # Process the report
            if 'scan_data' in report:
                scan_data = report['scan_data']
                for severity, findings in scan_data.items():
                    for finding in findings:
                        full_filename = finding.get('full_filename', 'Unknown Filename')

                        # Add the severity tag to the finding
                        finding['tag'] = severity

                        # Update CWE counts
                        cwe_ids = finding.get('cwe_ids', [])
                        for cwe_id in cwe_ids:
                            cwe_counts[cwe_id] += 1

                        # Check if this file is already in the formatted_data list
                        file_report = next((item for item in formatted_data if item['filename'] == full_filename), None)

                        if file_report:
                            # Append the finding to the existing entry
                            file_report['findings'].append(finding)
                        else:
                            # Create a new entry for this file
                            formatted_data.append({
                                'filename': full_filename,
                                'findings': [finding]
                            })

            cweid_list = [{"id": cweid, "count": count} for cweid, count in cwe_counts.items()]

            # Convert the timestamp to an ISO 8601 formatted string if it's a datetime object
            timestamp = report.get('timestamp')
            if isinstance(timestamp, datetime):
                timestamp = timestamp.isoformat()

            # Include _id and timestamp in the response
            response_data = {
                'id': str(report['_id']),
                'timestamp': timestamp,
                'reports': formatted_data,
                'cwe_counts': cweid_list
            }

            # Convert the response data dictionary to JSON
            formatted_data_json = json.dumps(response_data)

            # Return the JSON response
            return JsonResponse(json.loads(formatted_data_json), safe=False)

        except Exception as e:
            logger.error(f"Failed to fetch specific scan report: {e}")
            return JsonResponse({"error": "Failed to fetch specific scan report.", "details": str(e)}, status=500)




import pytz
from datetime import datetime
from django.http import JsonResponse
from collections import defaultdict
from bson import ObjectId

def specific_dynamic_scan_reports(request):
    # Define the IST timezone
    ist = pytz.timezone('Asia/Kolkata')

    # Get the report_id from the query parameters
    report_id = request.GET.get('report_id')

    if not report_id:
        return JsonResponse({"error": "report_id parameter is required."}, status=400)

    try:
        # Convert report_id to ObjectId if it is a valid ObjectId string
        try:
            report_id = ObjectId(report_id)
        except Exception as e:
            return JsonResponse({"error": "Invalid report_id format."}, status=400)

        # Fetch the specific report by report_id
        report = spider_scan_reports_collection.find_one({"_id": report_id})

        if not report:
            return JsonResponse({"error": "Report not found."}, status=404)

        # Initialize default dictionaries for overall counts
        overall_cweid_counts = defaultdict(int)
        overall_owasp_tag_counts = defaultdict(int)

        # Initialize a list to collect data
        formatted_data = []

        utc_timestamp = report['timestamp']

        # Convert UTC timestamp to IST
        if isinstance(utc_timestamp, datetime):
            utc_timestamp = utc_timestamp.replace(tzinfo=pytz.utc)  # Ensure the datetime is timezone-aware
        ist_timestamp = utc_timestamp.astimezone(ist)
        ist_timestamp_str = ist_timestamp.strftime('%Y-%m-%d %I:%M:%S %p')  # Format: 2024-08-18 07:12:40 PM

        # Calculate the number of endpoints and total number of alerts
        endpoints = list(report['report'].keys())
        num_endpoints = len(endpoints)
        total_alerts = sum(len(alert_data['alerts']) for alert_data in report['report'].values())

        # Initialize dictionaries for per-scan counts
        cweid_counts = defaultdict(int)
        owasp_tag_counts = defaultdict(int)

        # Build the report data and count occurrences
        formatted_report = []
        tickets = report.get('tickets', [])
        for endpoint, alert_data in report['report'].items():
            for alert in alert_data['alerts']:
                cweid = alert.get('cweid')
                if cweid and int(cweid) >= 0:
                    cweid_counts[cweid] += 1
                    overall_cweid_counts[cweid] += 1  # Update overall counts

                # Check and count OWASP tags
                tags = alert.get('tags', {})
                for tag_key in tags:
                    if tag_key.startswith('OWASP_2021_'):
                        tag_value = tag_key[-3:]  # Get the last three characters
                        owasp_tag_counts[tag_value] += 1
                        overall_owasp_tag_counts[tag_value] += 1  # Update overall counts

            formatted_report.append({
                "endpoint": endpoint,
                "alerts": alert_data['alerts']
            })

        cweid_list = [{"id": cweid, "count": count} for cweid, count in cweid_counts.items()]
        owasp_tag_list = [{"id": tag, "count": count} for tag, count in owasp_tag_counts.items()]

        # Append the data to formatted_data
        formatted_data.append({
            "id": str(report['_id']),
            "timestamp": ist_timestamp_str,
            "numEndpoints": num_endpoints,
            "totalAlerts": total_alerts,
            "cweidCounts": cweid_list,  # Per-scan CWE ID counts
            "owaspTagCounts": owasp_tag_list,  # Per-scan OWASP tag counts
            "report": formatted_report,
            "tickets" :tickets
        })

        # Convert overall counts to arrays
        overall_cweid_array = [{"cweid": cweid, "count": count} for cweid, count in overall_cweid_counts.items()]
        overall_owasp_tag_array = [{"tag": tag, "count": count} for tag, count in overall_owasp_tag_counts.items()]

        # Include both per-scan and overall arrays in the response
        response_data = {
            "reports": formatted_data,
            "overallCweidArray": overall_cweid_array,
            "overallOwaspTagArray": overall_owasp_tag_array
        }

        return JsonResponse(response_data, safe=False, json_dumps_params={'indent': 2})

    except Exception as e:
        return JsonResponse({"error": "Failed to fetch report.", "details": str(e)}, status=500)


from django.http import JsonResponse
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from pymongo import MongoClient
import os
from dotenv import load_dotenv
import logging
from bson import ObjectId

# Initialize the logger
logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()

# Retrieve MongoDB URI from environment variables
mongodb_uri = os.getenv('MONGODB_URI')
if not mongodb_uri:
    raise ValueError("MONGODB_URI environment variable not set")

try:
    # Create a MongoClient instance
    client = MongoClient(mongodb_uri)
    db = client.get_default_database()  # Use the default database if not specified in the URI

    # Define the collections
    ticket_collection = db['tickets']
except Exception as e:
    logger.error(f"Error connecting to MongoDB: {e}")
    raise


class TicketDetailView(View):
    @csrf_exempt
    def get(self, request):
        ticket_id = request.GET.get('ticket_id')

        if not ticket_id:
            return JsonResponse({'error': 'ticket_id parameter is required'}, status=400)

        try:
            # Convert ticket_id to ObjectId
            ticket_id = ObjectId(ticket_id)

            # Fetch the ticket from MongoDB
            ticket = ticket_collection.find_one({'_id': ticket_id})

            if ticket:
                # Format the ticket data
                ticket_data = {
                    'ticket_id': ticket.get('ticket_id'),
                    'unique_id': ticket.get('unique_id'),
                    'endpoint': ticket.get('endpoint'),
                    'title': ticket.get('title'),
                    'risk': ticket.get('risk'),
                    'risk_score': ticket.get('risk_score'),
                    'status': ticket.get('status'),
                    'description': ticket.get('description'),
                    'solution': ticket.get('solution'),
                    'reference': ticket.get('reference'),
                    'comments': ticket.get('comments', [])
                }

                return JsonResponse({'ticket': ticket_data, 'status': 'OK'}, safe=False)
            else:
                return JsonResponse({'error': 'Ticket not found'}, status=404)

        except Exception as e:
            logger.error(f"Error retrieving ticket: {e}")
            return JsonResponse({'error': 'Internal server error'}, status=500)