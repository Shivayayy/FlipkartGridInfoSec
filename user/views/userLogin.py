from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.hashers import check_password
from email_validator import validate_email, EmailNotValidError
from ..models import MongoUser, get_users_collection

class UserLoginView(APIView):
    def post(self, request):
        # Initialize MongoDB client and get collection
        users_collection = get_users_collection()

        data = request.data
        email = data.get('email')
        password = data.get('password')

        # Validate email and password
        if not email or not password:
            return Response({'error': 'Email and password are required'}, status=status.HTTP_400_BAD_REQUEST)

        # Validate email format
        try:
            validate_email(email)
        except EmailNotValidError:
            return Response({'error': 'Invalid email address'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if user exists
        user_data = users_collection.find_one({'email': email})
        if not user_data:
            return Response({'error': 'Invalid email or password'}, status=status.HTTP_400_BAD_REQUEST)

        # Verify password
        if not check_password(password, user_data['password']):
            return Response({'error': 'Invalid email or password'}, status=status.HTTP_400_BAD_REQUEST)

        mongo_user = MongoUser(user_data)

        # Generate JWT tokens
        refresh = RefreshToken.for_user(mongo_user)
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)

        return Response({
            'refresh': refresh_token,
            'access': access_token,
            'message': 'Login successful'
        }, status=status.HTTP_200_OK)
