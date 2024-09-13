from django.http import JsonResponse, HttpResponseBadRequest, HttpResponseNotFound
from django.views.decorators.csrf import csrf_exempt
import json
from .mongo_connection import insert_ticket, get_all_tickets, get_ticket, update_ticket, delete_ticket, ticket_exists,add_comment,get_next_ticket_id
from pymongo import MongoClient
from datetime import datetime
import os
from dotenv import load_dotenv
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()


@csrf_exempt
def create_ticket(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            unique_id = data.get('unique_id')

            # Check if ticket with this unique_id already exists
            if ticket_exists(unique_id):
                return JsonResponse({'error': 'Ticket already exists'}, status=400)

            # Generate sequential ticket_id
            ticket_id = get_next_ticket_id()

            # Add sequential ticket_id to data
            data['ticket_id'] = ticket_id

            # Ensure all required fields are present
            required_fields = ['unique_id', 'endpoint', 'title', 'risk', 'status', 'description']
            if not all(field in data for field in required_fields):
                return JsonResponse({'error': 'Missing required fields'}, status=400)

            # Insert ticket into MongoDB
            insert_ticket(data)
            return JsonResponse({'message': 'Ticket created successfully'}, status=201)

        except json.JSONDecodeError:
            return HttpResponseBadRequest("Invalid JSON data")

    return HttpResponseBadRequest("Invalid request method")


@csrf_exempt
def get_ticket_view(request, ticket_id):
    if request.method == 'GET':
        # Ensure ticket_id is treated as an integer
        try:
            ticket_id = int(ticket_id)
        except ValueError:
            return HttpResponseBadRequest("Invalid ticket ID format")

        ticket = get_ticket(ticket_id)
        if ticket:
            return JsonResponse(ticket, safe=False)
        return HttpResponseNotFound("Ticket not found")
    return HttpResponseBadRequest("Invalid request method")


def get_all_tickets_view(request):
    if request.method == 'GET':
        tickets = get_all_tickets()
        return JsonResponse(tickets, safe=False)
    return HttpResponseBadRequest("Invalid request method")

from django.http import JsonResponse, HttpResponseNotFound, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
import json

@csrf_exempt
def update_ticket_view(request, ticket_id):
    print(f"Received request method: {request.method}")  # Debugging line

    try:
        ticket_id = int(ticket_id)  # Convert ticket_id to integer
    except ValueError:
        return HttpResponseBadRequest("Invalid ticket ID")

    if request.method == 'PUT':
        print("PUT method detected")  # Debugging line
        try:
            updates = json.loads(request.body)
            valid_fields = ['endpoint', 'title', 'risk', 'status', 'description']
            updates = {k: v for k, v in updates.items() if k in valid_fields}

            if update_ticket(ticket_id, updates):
                return JsonResponse({'message': 'Ticket updated successfully'})
            return HttpResponseNotFound("Ticket not found")
        except json.JSONDecodeError:
            return HttpResponseBadRequest("Invalid JSON data")
    return HttpResponseBadRequest("Invalid request method")



@csrf_exempt
def delete_ticket_view(request, ticket_id):
    try:
        ticket_id = int(ticket_id)  # Convert ticket_id to integer
    except ValueError:
        return HttpResponseBadRequest("Invalid ticket ID")
    if request.method == 'DELETE':
        if delete_ticket(ticket_id):
            return JsonResponse({'message': 'Ticket deleted successfully'})
        return HttpResponseNotFound("Ticket not found")
    return HttpResponseBadRequest("Invalid request method")


@csrf_exempt
def add_comment_view(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            ticket_id = data.get('ticket_id')
            comment = data.get('comment')

            if not ticket_id or not comment:
                return JsonResponse({'error': 'Missing required fields'}, status=400)

            if add_comment(ticket_id, comment):
                return JsonResponse({'message': 'Comment added successfully'})
            return HttpResponseNotFound("Ticket not found")
        except json.JSONDecodeError:
            return HttpResponseBadRequest("Invalid JSON data")
    return HttpResponseBadRequest("Invalid request method")
