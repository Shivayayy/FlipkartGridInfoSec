import os
from dotenv import load_dotenv
from pymongo import MongoClient
import logging

# Configure logging
logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()

# Initialize MongoDB client and collection using environment variables
mongodb_uri = os.getenv('MONGODB_URI')
if mongodb_uri is None:
    raise ValueError("MONGODB_URI environment variable not set")

client = MongoClient(mongodb_uri)
db = client.get_default_database()  # Use the default database if not specified in the URI
api_inventory_collection = db['apiEndpointInventory']

def fetch_unique_endpoints():
    """Fetch unique endpoints (paths) from the MongoDB collection."""
    try:
        return api_inventory_collection.distinct('path')
    except Exception as e:
        # Log the error message
        logger.error(f"An error occurred while fetching unique endpoints: {e}")
        # Return an empty list or handle as needed
        return []
