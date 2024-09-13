from __future__ import absolute_import, unicode_literals
from pymongo import MongoClient
from datetime import datetime
import os
from dotenv import load_dotenv
import logging
import json

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


def store_scan_report(scan_data):
    try:
        # Parse the JSON data if it's a string
        if isinstance(scan_data, str):
            scan_data = json.loads(scan_data)

        # Add metadata to the report
        report = {
            "timestamp": datetime.utcnow(),
            "scan_data": scan_data
        }

        # Insert the report into the database
        result = scan_reports_collection.insert_one(report)

        logger.info(f"Scan report stored successfully with ID: {result.inserted_id}")
        return str(result.inserted_id)

    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse scan data: {e}")
        raise
    except Exception as e:
        logger.error(f"Failed to store scan report: {e}")
        raise
