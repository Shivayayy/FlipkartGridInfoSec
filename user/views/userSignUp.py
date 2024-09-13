from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.hashers import make_password
from email_validator import validate_email, EmailNotValidError
from pymongo import MongoClient
from django.conf import settings
import jwt
import datetime

class UserSignUpView(APIView):
    def post(self, request):
        # Initialize MongoDB client
        mongodb_uri = getattr(settings, 'MONGODB_URI', None)
        if mongodb_uri is None:
            raise ValueError("MONGODB_URI setting not found")

        client = MongoClient(mongodb_uri)
        db = client.get_default_database()
        users_collection = db['users']
        organizations_collection = db['organizations']

        data = request.data
        email = data.get('email')
        password = data.get('password')
        confirm_password = data.get('confirm_password')
        full_name = data.get('full_name')
        job_title = data.get('job_title')
        company_name = data.get('company_name')
        phone_number = data.get('phone_number', None)
        organization_name = data.get('organization_name')
        organization_exist = data.get('organization_exist', 'notok')  # Default to 'notok' if not provided

        # Validate all required fields are present
        if not all([email, password, confirm_password, full_name, job_title, company_name, organization_name]):
            return Response({'error': 'All required fields must be provided'}, status=status.HTTP_400_BAD_REQUEST)

        # Validate email
        try:
            validate_email(email)
        except EmailNotValidError:
            return Response({'error': 'Invalid email address'}, status=status.HTTP_400_BAD_REQUEST)

        # Validate passwords match
        if password != confirm_password:
            return Response({'error': 'Passwords do not match'}, status=status.HTTP_400_BAD_REQUEST)

        # Password validation logic
        if len(password) < 8 or not any(char.isdigit() for char in password) or not any(char.isupper() for char in password) or not any(char.islower() for char in password):
            return Response({
                'error': 'Password must be 8 characters long, contain an uppercase letter, a lowercase letter, and a number.'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Check if email is already registered in MongoDB
        if users_collection.find_one({'email': email}):
            return Response({'error': 'User with this email already exists'}, status=status.HTTP_400_BAD_REQUEST)

        # Handle organization logic
        organization_id = None
        if organization_exist == 'notok':
            create_organization_response, organization_id = self._create_organization(data, organizations_collection)
            if create_organization_response.status_code != status.HTTP_201_CREATED:
                return create_organization_response  # If org creation fails, return the error response
        else:
            # Fetch existing organization ID
            existing_organization = organizations_collection.find_one({'name': organization_name})
            if existing_organization:
                organization_id = existing_organization['_id']
            else:
                return Response({'error': 'Organization does not exist'}, status=status.HTTP_400_BAD_REQUEST)

        # Store user data in MongoDB
        hashed_password = make_password(password)
        user_data = {
            'email': email,
            'password': hashed_password,
            'full_name': full_name,
            'job_title': job_title,
            'company_name': company_name,
            'phone_number': phone_number,
            'organization_name': organization_name,
            'organization_id': organization_id  # Store organization ID here
        }

        user_id = users_collection.insert_one(user_data).inserted_id

        # Generate JWT tokens manually
        expiration = datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Token expiry time
        secret_key = getattr(settings, 'SECRET_KEY', 'your_secret_key')
        access_token = jwt.encode({'user_id': str(user_id), 'exp': expiration}, secret_key, algorithm='HS256')
        refresh_token = jwt.encode({'user_id': str(user_id)}, secret_key, algorithm='HS256')

        return Response({
            'refresh': refresh_token,
            'access': access_token,
            'message': 'User registered successfully'
        }, status=status.HTTP_201_CREATED)

    def _create_organization(self, data, organizations_collection):
        """
        This method creates a new organization if required.
        """
        org_name = data.get('organization_name')
        approx_number_of_apis = data.get('approx_number_of_apis')
        github_url = data.get('github_url')
        access_token = data.get('access_token')
        domain = data.get('domain')

        if not all([org_name, approx_number_of_apis, github_url, access_token]):
            return Response({'error': 'All required fields must be provided'}, status=status.HTTP_400_BAD_REQUEST), None

        # Check if the organization already exists
        existing_organization = organizations_collection.find_one({'name': org_name})
        if existing_organization:
            return Response({'error': 'Organization with this name already exists'}, status=status.HTTP_400_BAD_REQUEST), existing_organization['_id']

        # Store organization data in MongoDB
        organization_data = {
            'name': org_name,
            'approx_number_of_apis': approx_number_of_apis,
            'github_url': github_url,
            'access_token': access_token,
            'domain': domain,
        }
        result = organizations_collection.insert_one(organization_data)
        return Response({'message': 'Organization created successfully'}, status=status.HTTP_201_CREATED), result.inserted_id
