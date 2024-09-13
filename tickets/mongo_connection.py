import os
from pymongo import MongoClient
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Retrieve MongoDB URI from environment variables
mongodb_uri = os.getenv('MONGODB_URI')
if mongodb_uri is None:
    raise ValueError("MONGODB_URI environment variable not set")

# Create a MongoClient instance
client = MongoClient(mongodb_uri)

# Get the default database
db = client.get_default_database()

# Define collections
ticket_collection = db['tickets']

def serialize_ticket(ticket):
    # Convert ObjectId to string
    if '_id' in ticket:
        ticket['_id'] = str(ticket['_id'])
    return ticket

def insert_ticket(ticket):
    result = ticket_collection.insert_one(ticket)
    # Return the inserted ticket with ObjectId converted to string
    #return serialize_ticket(ticket_collection.find_one({'_id': result.inserted_id}))

def get_all_tickets():
    tickets = list(ticket_collection.find())
    # Convert ObjectId to string
    for ticket in tickets:
        ticket['_id'] = str(ticket['_id'])
    return tickets

def get_ticket(ticket_id):
    ticket = ticket_collection.find_one({'ticket_id': ticket_id})
    if ticket:
        # Convert ObjectId to string
        ticket['_id'] = str(ticket['_id'])
    return ticket

def update_ticket(ticket_id, updates):
    result = ticket_collection.update_one({'ticket_id': ticket_id}, {'$set': updates})
    return result.modified_count > 0

def delete_ticket(ticket_id):
    result = ticket_collection.delete_one({'ticket_id': ticket_id})
    return result.deleted_count > 0

def ticket_exists(unique_id):
    return ticket_collection.count_documents({'unique_id': unique_id}) > 0

def add_comment(ticket_id, comment):
    """Add a comment to a ticket."""
    result = ticket_collection.update_one(
        {'ticket_id': ticket_id},
        {'$push': {'comments': comment}}
    )
    return result.modified_count > 0

def get_next_ticket_id():
    # Find the maximum current ticket_id and increment it by 1
    last_ticket = ticket_collection.find_one(sort=[("ticket_id", -1)])
    return (last_ticket['ticket_id'] + 1) if last_ticket else 1