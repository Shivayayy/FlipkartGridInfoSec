import jwt
from pymongo import MongoClient
from django.conf import settings
from rest_framework.exceptions import AuthenticationFailed


# Utility function to extract the JWT token from the header and decode it
def get_user_org_domain(request):
    """
    Extract JWT token from request, decode it to get user info,
    and find the user's organization domain.
    """

    # 1. Get JWT Token from Authorization header
    auth_header = request.headers.get('Authorization', None)
    if auth_header is None or not auth_header.startswith('Bearer '):
        raise AuthenticationFailed('JWT token missing or malformed in Authorization header')

    # Extract the JWT token
    token = auth_header.split(' ')[1]

    try:
        # 2. Decode JWT Token
        decoded_token = jwt.decode(
            token,
            settings.SIMPLE_JWT['SIGNING_KEY'],
            algorithms=['HS256']
        )
        user_id = decoded_token.get('user_id')  # Assuming 'user_id' is in the JWT payload

        if not user_id:
            raise AuthenticationFailed('Invalid token: user ID not found')

        # 3. Connect to MongoDB and find the user's organization
        mongodb_uri = settings.MONGODB_URI
        client = MongoClient(mongodb_uri)
        db = client.get_default_database()

        # Find the user in MongoDB using the user_id from the JWT token
        users_collection = db['users']
        user = users_collection.find_one({'_id': user_id})

        if not user:
            raise AuthenticationFailed('User not found')

        # 4. Retrieve the user's organizations and return the domain
        org_id = user.get('organization_id')  # Assuming organization_id is stored in user
        if not org_id:
            raise AuthenticationFailed('User does not belong to any organization')

        # Find the organization based on org_id
        organizations_collection = db['organizations']
        organization = organizations_collection.find_one({'_id': org_id})

        if not organization:
            raise AuthenticationFailed('Organization not found')

        domain = organization.get('domain')
        if not domain:
            raise AuthenticationFailed('Organization does not have a domain')

        return domain

    except jwt.ExpiredSignatureError:
        raise AuthenticationFailed('Token has expired')
    except jwt.InvalidTokenError:
        raise AuthenticationFailed('Invalid token')

