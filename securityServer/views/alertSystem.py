from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from pymongo import MongoClient
from bson import ObjectId
from django.conf import settings
from datetime import datetime
import json

# Initialize MongoDB client
mongodb_uri = getattr(settings, 'MONGODB_URI', None)
if mongodb_uri is None:
    raise ValueError("MONGODB_URI setting not found")

client = MongoClient(mongodb_uri)
db = client.get_default_database()
api_inventory_collection = db['apiEndpointInventory']
notification_collection = db['notifications']

@csrf_exempt
def handle_notification_update(request):
    if request.method == 'POST':
        try:
            # Parse the JSON data from the request
            data = json.loads(request.body)
            notification_id = data.get('notification_id')
            status = data.get('status')
            path = data.get('path')

            if not notification_id or not status or not path:
                return JsonResponse({'error': 'Missing required fields'}, status=400)

            # Convert the notification_id to an ObjectId
            try:
                notification_id = ObjectId(notification_id)
            except Exception as e:
                return JsonResponse({'error': 'Invalid notification_id format'}, status=400)

            # Check the status and perform the appropriate actions
            if status == 'allow':
                # Update the api_inventory_collection
                endpoint = f"POST {path}"
                api_inventory_collection.update_one(
                    {'path': path},
                    {'$set': {'status': 'active', 'last_seen': datetime.utcnow()}}
                )

                # Delete the notification from notification_collection
                result = notification_collection.delete_one({'_id': notification_id})
                if result.deleted_count == 0:
                    return JsonResponse({'error': 'Notification not found'}, status=404)

            elif status == 'deny':
                # Update the notification in notification_collection
                result = notification_collection.update_one(
                    {'_id': notification_id},
                    {'$set': {'notification_code': '4'}}
                )
                if result.matched_count == 0:
                    return JsonResponse({'error': 'Notification not found'}, status=404)

            else:
                return JsonResponse({'error': 'Invalid status'}, status=400)

            return JsonResponse({'message': 'Operation completed successfully'}, status=200)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Method not allowed'}, status=405)
