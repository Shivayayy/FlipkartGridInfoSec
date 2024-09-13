from datetime import datetime
from pymongo import MongoClient
import os
from dotenv import load_dotenv
from bson import ObjectId  # Make sure this import is present
from ..DataBaseAccess.api_inventory_service import update_api_inventory_task

# Load environment variables from .env file
load_dotenv()

# Initialize MongoDB client and collection using environment variables
mongodb_uri = os.getenv('MONGODB_URI')
client = MongoClient(mongodb_uri)
db = client.get_default_database()  # Use the default database if not specified in the URI
api_req_inventory_collection = db['apiReqInventory']
real_time_api_collection =db['realTime']

def store_api_req_task(request, response):
    """
    Store the request and response information in the 'apiReqInventory' collection and update the API inventory.
    """
    try:
        # Generate a unique request ID
        request_id = str(ObjectId())

        # Extract information from the request
        method = request.method
        path = request.path
        timestamp = datetime.utcnow()

        # Extract request data
        real_time ={
            "path": request.path,
            "timestamp": timestamp,
        }
        request_data = {
            'request_id': request_id,
            'timestamp': timestamp,
            'method': method,
            'path': path,
            'request_headers': dict(request.headers),
            'request_body': request.body.decode('utf-8', errors='ignore'),
            'request_cookies': request.COOKIES
        }

        # Extract response data
        response_data = {
            'response_status_code': response.status_code,
            'response_headers': dict(response.headers),
            'response_body': response.content.decode('utf-8', errors='ignore')
        }

        # Combine request and response data
        combined_data = {
            **request_data,
            **response_data
        }

        # Store the request and response information into the 'apiReqInventory' collection
        api_req_inventory_collection.insert_one(combined_data)
        real_time_api_collection.insert_one(real_time)

        # Update the API endpoint inventory synchronously
        if method and path:
            update_api_inventory_task(method, path)

    except Exception as e:
        # Handle exceptions (e.g., log the error)
        print(f"An error occurred: {e}")
