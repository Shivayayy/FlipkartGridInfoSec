from django.contrib.auth.models import AbstractBaseUser
from pymongo import MongoClient
from django.conf import settings

class MongoUser(AbstractBaseUser):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.email = user_data['email']
        self.password = user_data['password']

# Helper function to get MongoDB client
def get_mongodb_client():
    mongodb_uri = getattr(settings, 'MONGODB_URI', None)
    if mongodb_uri is None:
        raise ValueError("MONGODB_URI setting not found")
    return MongoClient(mongodb_uri)

# Helper function to get users collection
def get_users_collection():
    client = get_mongodb_client()
    db = client.get_default_database()  # get the default database
    return db['users']  # users collection
