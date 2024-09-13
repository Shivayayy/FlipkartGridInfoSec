# securityServer/views/traffic_view.py
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from pymongo import MongoClient
from datetime import datetime, timedelta
import os
import time
import logging
import json

# Configure logging
logger = logging.getLogger(__name__)

# Initialize MongoDB client
mongodb_uri = getattr(settings, 'MONGODB_URI', None)
if mongodb_uri is None:
    logger.error("MONGODB_URI setting not found")
    raise ValueError("MONGODB_URI setting not found")


client = MongoClient(mongodb_uri)
db = client.get_default_database()
per_second_collection = db['realTime']

@csrf_exempt
def get_requests_per_second(request):
    if request.method == 'POST':
        # Get the endpoint path from the request body
        body = json.loads(request.body)
        endpoint_path = body.get('endpoint')

        if not endpoint_path:
            return JsonResponse({'error': 'Endpoint path is required'}, status=400)

        # Get the current timestamp and one second ago
        now = time.time()
        one_second_ago = now - 1

        # Query the logs for requests to the specified endpoint in the last second
        count =per_second_collection.count_documents({
            "path": endpoint_path,
            "timestamp": {"$gte": one_second_ago, "$lte": now}
        })

        # Return the count as requests per second
        return JsonResponse({"requests_per_second": count}, status=200)

    return JsonResponse({'error': 'Only POST method allowed'}, status=405)
