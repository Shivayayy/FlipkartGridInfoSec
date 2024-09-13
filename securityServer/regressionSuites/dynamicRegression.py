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


class DynamicRegression(View):

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
        return JsonResponse({'results': "dynamic testing completed", 'status': "OK"})
