from celery import shared_task
from pymongo import MongoClient
from django.conf import settings
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize MongoDB client
mongodb_uri = getattr(settings, 'MONGODB_URI', None)
if mongodb_uri is None:
    logger.error("MONGODB_URI setting not found")
    raise ValueError("MONGODB_URI setting not found")

client = MongoClient(mongodb_uri)
db = client.get_default_database()
scan_reports_collection = db['spiderScanReports']

@shared_task
def store_scan_report_task(scan_report, ticket_ids):
    try:
        scan_reports_collection.insert_one({
            'timestamp': datetime.utcnow(),
            'report': scan_report,
            'tickets': ticket_ids,
        })
        logger.info("Scan report stored successfully.")
    except Exception as e:
        logger.error(f"An error occurred while storing the scan report: {e}")
