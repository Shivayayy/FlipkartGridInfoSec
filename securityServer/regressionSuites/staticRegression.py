import subprocess
import json
import os
from django.http import JsonResponse
from django.views import View
from ..DataBaseAccess.store_bearer_report import store_scan_report
from pymongo import MongoClient
import logging
from django.conf import settings
logger = logging.getLogger(__name__)
import time

# Initialize MongoDB client
mongodb_uri = getattr(settings, 'MONGODB_URI', None)
if mongodb_uri is None:
    logger.error("MONGODB_URI setting not found")
    raise ValueError("MONGODB_URI setting not found")

client = MongoClient(mongodb_uri)
db = client.get_default_database()
notification_collection = db['notifications']

class StaticRegression(View):
    def get(self, request):
        time.sleep(60)
        return JsonResponse({"status" :"ok"}, safe=False)

