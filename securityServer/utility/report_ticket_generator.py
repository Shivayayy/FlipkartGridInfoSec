
from pymongo import MongoClient
import os
from dotenv import load_dotenv
import logging
from bson import ObjectId

# Initialize the logger
logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()

# Retrieve MongoDB URI from environment variables
mongodb_uri = os.getenv('MONGODB_URI')
if not mongodb_uri:
    raise ValueError("MONGODB_URI environment variable not set")

try:
    # Create a MongoClient instance
    client = MongoClient(mongodb_uri)
    db = client.get_default_database()  # Use the default database if not specified in the URI

    # Define the collections
    ticket_collection = db['tickets']
    scan_reports_collection = db['spiderScanReports']
except Exception as e:
    logger.error(f"Error connecting to MongoDB: {e}")
    raise

# Helper functions
def get_next_ticket_id():
    # Find the maximum current ticket_id and increment it by 1
    last_ticket = ticket_collection.find_one(sort=[("ticket_id", -1)])
    return (last_ticket['ticket_id'] + 1) if last_ticket else 1

def insert_ticket(ticket):
    ticket_collection.insert_one(ticket)

def ticket_exists(unique_id):
    return ticket_collection.count_documents({'unique_id': unique_id}) > 0

def get_and_store_tickets(scan_report):
    generated_ticket_ids = []

    try:
        # There's only one key in the outer dictionary, which is the API endpoint
        api_endpoint = list(scan_report.keys())[0]
        alerts = scan_report[api_endpoint].get('alerts', [])

        if api_endpoint.startswith("https://onlineshop-psi-seven.vercel.app"):
            api_endpoint = api_endpoint[len("https://onlineshop-psi-seven.vercel.app"):]

        for alert in alerts:
            unique_id = f"{api_endpoint}_{alert.get('name', 'Unknown')}"
            ticket_id = get_next_ticket_id()
            ticket = {
                'ticket_id': ticket_id,
                'unique_id': unique_id,
                'endpoint': api_endpoint,
                'title': alert.get('name', 'Unknown'),
                'risk': alert.get('risk', 'Unknown'),
                'risk_score': alert.get('risk_score', 0),
                'status': 'OPEN',
                'description': alert.get('description', 'No description provided'),
                'solution': alert.get('solution', 'No solution provided'),
                'reference': alert.get('reference', 'No reference provided'),
                'comments': []
            }

            if not ticket_exists(unique_id):
                insert_ticket(ticket)
                logger.info(f"Ticket generated successfully: {ticket_id}")
            else:
                logger.info(f"Ticket already exists: {unique_id}")

            # Add the ticket ID to the list, even if it already exists
            existing_ticket = ticket_collection.find_one({'unique_id': unique_id}, {'_id': 1})
            if existing_ticket:
                generated_ticket_ids.append(existing_ticket['_id'])  # Store ObjectId

    except Exception as e:
        logger.error(f"Error processing scan report: {e}")
        raise

    # Fetch full ticket details using generated IDs, excluding the _id field
    full_tickets = list(ticket_collection.find(
        {'_id': {'$in': generated_ticket_ids}},
        {'_id': 0}  # Exclude the _id field
    ))

    return full_tickets
