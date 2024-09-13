import logging
from celery import shared_task
from pymongo import MongoClient
from datetime import datetime
from django.core.mail import send_mail
from django.conf import settings

# Configure logging
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

# Initialize MongoDB client
mongodb_uri = getattr(settings, 'MONGODB_URI', None)
if mongodb_uri is None:
    logger.error("MONGODB_URI setting not found")
    raise ValueError("MONGODB_URI setting not found")

client = MongoClient(mongodb_uri)
db = client.get_default_database()
api_inventory_collection = db['apiEndpointInventory']
notification_collection = db['notifications']


@shared_task
def update_api_inventory_task(method, path, average_risk_score=None, risk_factor=None):
    logger.error(f"Received task with method: {method}, path: {path}")

    # Validate input
    if not method or not path:
        logger.error("Method or path is empty")
        return "Method or path is empty"

    # Process path
    path = path.rstrip('/')
    if not path.startswith('/api/'):
        return

    method = method.upper()
    endpoint = f"{method} {path}"

    # Prepare update fields
    update_fields = {'last_seen': datetime.utcnow()}
    if average_risk_score is not None:
        update_fields['average_risk_score'] = average_risk_score
    if risk_factor is not None:
        update_fields['risk_factor'] = risk_factor

    # Update or insert endpoint
    existing_entry = api_inventory_collection.find_one({'endpoint': endpoint})
    if existing_entry:
        api_inventory_collection.update_one(
            {'endpoint': endpoint},
            {'$set': update_fields}
        )
        logger.error(f"Updated existing endpoint: {endpoint}")
    else:
        api_inventory_collection.insert_one({
            'endpoint': endpoint,
            'method': method,
            'path': path,
            'status': "Testing",
            'first_seen': datetime.utcnow(),
            'last_seen': datetime.utcnow(),
            'average_risk_score': average_risk_score if average_risk_score is not None else 0,
            'risk_factor': risk_factor if risk_factor is not None else 'Basic'
        })
        logger.error(f"Inserted new endpoint: {endpoint}")

        # Attempt to send email and add notification
        try:
            logger.error("Preparing to send email...")

            send_mail(
                'New API Endpoint Added',
                f'A new API endpoint has been added to the dashboard: {endpoint}',
                getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@example.com'),
                ['shivamdwivedi67000@gmail.com'],
                fail_silently=False,
            )

            # Add notification to the database
            notification = {
                'notification_code' :'3',
                'tag': 'new_api_detected',
                'message': 'New API detected',
                'endpoint_name': endpoint,
                'api_path': path,
                'timestamp': datetime.utcnow()
            }
            notification_collection.insert_one(notification)
            #logger.error(f"Email sent successfully to {'shivamdwivedi67000@gmail.com'}")
            logger.error(f"Notification added to database: {notification}")

        except Exception as e:
            logger.error(f"Error sending email or adding notification: {str(e)}", exc_info=True)
            # Re-raise the exception to see it in Celery logs
            raise

    return f"Processed endpoint: {endpoint}"