import json
from bson import ObjectId
from bson.json_util import dumps
from django.http import JsonResponse
from pymongo import MongoClient
from django.conf import settings
from django.views.decorators.http import require_http_methods
import logging

# Configure logging
logger = logging.getLogger(__name__)

# Initialize MongoDB client
mongodb_uri = getattr(settings, 'MONGODB_URI', None)
if mongodb_uri is None:
    logger.error("MONGODB_URI setting not found")
    raise ValueError("MONGODB_URI setting not found")

client = MongoClient(mongodb_uri)
db = client.get_default_database()
notification_collection = db['notifications']

@require_http_methods(["GET"])
def fetch_notifications_view(request):
    try:
        # Fetch all notifications from the collection
        notifications = list(notification_collection.find())

        # Convert MongoDB documents to JSON-friendly format
        notifications_json = json.loads(dumps(notifications))

        # Return the notifications as a JSON response
        return JsonResponse({'notifications': notifications_json}, safe=False, status=200)

    except Exception as e:
        logger.error(f"Error fetching notifications: {str(e)}", exc_info=True)
        return JsonResponse({'error': 'Failed to fetch notifications'}, status=500)
