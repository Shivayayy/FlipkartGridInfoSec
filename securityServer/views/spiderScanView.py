from django.views import View
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
import requests
import time
import logging
import os
from dotenv import load_dotenv
from pymongo import MongoClient
from django.conf import settings

# Load environment variables from .env file
load_dotenv()

# Utility imports
from ..DataBaseAccess.api_inventory_service import update_api_inventory_task
from ..DataBaseAccess.fetch_unique_endpoints import fetch_unique_endpoints
from ..DataBaseAccess.store_scan_reports import store_scan_report_task
from ..utility.convert_risk_to_score import convert_risk_to_score
from ..utility.determine_risk_factor import determine_risk_factor
from ..utility.report_ticket_generator import get_and_store_tickets

logger = logging.getLogger(__name__)

# Initialize MongoDB client
mongodb_uri = getattr(settings, 'MONGODB_URI', None)
if mongodb_uri is None:
    logger.error("MONGODB_URI setting not found")
    raise ValueError("MONGODB_URI setting not found")

client = MongoClient(mongodb_uri)
db = client.get_default_database()
notification_collection = db['notifications']


class SpiderScanView(View):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.zap_base_url = os.getenv('ZAP_BASE_URL', 'http://localhost:8080')
        self.zap_api_key = os.getenv('ZAP_API_KEY', '')

    def start_spider_scan(self, url):
        api_url = f'{self.zap_base_url}/JSON/spider/action/scan/?apikey={self.zap_api_key}&url={url}&recurse=true'
        response = requests.get(api_url)
        response.raise_for_status()
        json_data = response.json()
        return json_data.get('scan', '')

    def get_scan_status(self, scan_id):
        api_url = f'{self.zap_base_url}/JSON/spider/view/status/?apikey={self.zap_api_key}&scanId={scan_id}'
        response = requests.get(api_url)
        response.raise_for_status()
        json_data = response.json()
        return int(json_data.get('status', 0))

    def start_active_scan(self, url):
        api_url = f'{self.zap_base_url}/JSON/ascan/action/scan/?apikey={self.zap_api_key}&url={url}&recurse=true'
        response = requests.get(api_url)
        response.raise_for_status()
        json_data = response.json()
        return json_data.get('scan', '')

    def get_active_scan_status(self, scan_id):
        api_url = f'{self.zap_base_url}/JSON/ascan/view/status/?apikey={self.zap_api_key}&scanId={scan_id}'
        response = requests.get(api_url)
        response.raise_for_status()
        json_data = response.json()
        return int(json_data.get('status', 0))

    def fetch_alerts(self, url):
        api_url = f'{self.zap_base_url}/JSON/core/view/alerts/?apikey={self.zap_api_key}&baseurl={url}&start=0&count=100'
        response = requests.get(api_url)
        response.raise_for_status()
        json_data = response.json()
        return json_data.get('alerts', [])

    @method_decorator(csrf_exempt)
    def get(self, request):
        base_url = 'https://onlineshop-psi-seven.vercel.app'
        results = []
        scan_report = {}

        try:
            # Fetch unique endpoints from MongoDB
            unique_endpoints = fetch_unique_endpoints()

            for path in unique_endpoints:
                full_url = f'{base_url}{path}'

                # Start Spider Scan
                scan_id = self.start_spider_scan(full_url)
                if not scan_id:
                    results.append({'url': full_url, 'error': 'Spider scan failed to start'})
                    continue

                # Monitor Spider Scan Status
                while True:
                    status = self.get_scan_status(scan_id)
                    if status == 100:
                        break
                    time.sleep(10)  # Wait before checking the status again

                # Start Active Scan
                active_scan_id = self.start_active_scan(full_url)
                if not active_scan_id:
                    results.append({'url': full_url, 'error': 'Active scan failed to start'})
                    continue

                # Monitor Active Scan Status
                while True:
                    status = self.get_active_scan_status(active_scan_id)
                    if status == 100:
                        break
                    time.sleep(10)  # Wait before checking the status again

                # Fetch Alerts from the Active Scan
                alerts = self.fetch_alerts(full_url)

                # Process Alerts and Compute Risk Score
                risk_scores = []
                if full_url not in scan_report:
                    scan_report[full_url] = {'alerts': []}

                for alert in alerts:
                    risk = alert.get('risk', 'Informational')
                    risk_score = convert_risk_to_score(risk)
                    risk_scores.append(risk_score)

                    scan_report[full_url]['alerts'].append({
                        'sourceid': alert.get('sourceid'),
                        'method': alert.get('method'),
                        'evidence': alert.get('evidence'),
                        'pluginId': alert.get('pluginId'),
                        'cweid': alert.get('cweid'),
                        'confidence': alert.get('confidence'),
                        'wascid': alert.get('wascid'),
                        'description': alert.get('description'),
                        'messageId': alert.get('messageId'),
                        'inputVector': alert.get('inputVector'),
                        'url': alert.get('url'),
                        'tags': alert.get('tags'),
                        'reference': alert.get('reference'),
                        'solution': alert.get('solution'),
                        'alert': alert.get('alert'),
                        'param': alert.get('param'),
                        'attack': alert.get('attack'),
                        'name': alert.get('name'),
                        'risk': risk,
                        'risk_score': risk_score,
                        'id': alert.get('id'),
                        'alertRef': alert.get('alertRef')
                    })

                average_risk_score = sum(risk_scores) / len(risk_scores) if risk_scores else 0
                risk_factor = determine_risk_factor(average_risk_score)

                # Update the api_endpoints_collection with the average risk score and risk factor
                update_api_inventory_task.delay('GET', path, average_risk_score, risk_factor)

            # Store the formatted data in MongoDB and create notification
            if scan_report:
                tickets = get_and_store_tickets(scan_report)  # Retrieve all ticket IDs

                # Store scan report
                report_task = store_scan_report_task.delay(scan_report, tickets)

                # Wait for the task to complete and get the result
                report_id = report_task.get()  # Ensure this line handles the task completion properly

                # Create Notification
                notification_data = {
                    'notification_code': '5',
                    'tag': 'manual_scan_triggered',
                    'message': 'Dynamic Scanning for latest scan completed. Tap to view report',
                    'report_id': report_id
                }
                notification_collection.insert_one(notification_data)

            return JsonResponse({'results': results, 'status': "OK"}, safe=False)

        except Exception as e:
            logger.error(f"Error in scan_endpoints: {e}")
            return JsonResponse({'error': str(e)}, status=500)
