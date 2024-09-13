import logging
import json
from django.http import HttpResponseForbidden
from ..DataBaseAccess.store_api_req import store_api_req_task

logger = logging.getLogger(__name__)


class SecurityMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if self.check_security(request):
            response = self.get_response(request)
            self.log_response(request, response)
            return response
        return HttpResponseForbidden("Access denied due to security concerns.")

    def check_security(self, request):
        method = request.method
        path = request.path
        ip = request.META.get('REMOTE_ADDR')

        logger.info(f"Request: {method} {path} from {ip}")
        logger.info(f"Headers: {dict(request.headers)}")

        if method in ['POST', 'PUT', 'PATCH']:
            body = request.body.decode('utf-8', errors='ignore')
            try:
                body_json = json.loads(body)
                logger.info(f"Request Body: {json.dumps(body_json, indent=2)}")
            except json.JSONDecodeError:
                logger.info(f"Request Body: {body}")

        return True

    def log_response(self, request, response):
        logger.info(f"Response Status: {response.status_code}")
        logger.info(f"Response Headers: {dict(response.headers)}")

        content_type = response.get('Content-Type', '')

        # Initialize body variable
        body = None

        # Handle JSON content type
        if content_type.startswith('application/json'):
            try:
                body = response.content.decode('utf-8')
                body_json = json.loads(body)
                logger.info(f"Response Body: {json.dumps(body_json, indent=2)}")
            except (UnicodeDecodeError, json.JSONDecodeError) as e:
                logger.error(f"Failed to decode JSON response body: {e}")
                if body is not None:
                    logger.info(f"Response Body (partial): {body}")

        # Handle non-JSON content types
        else:
            try:
                body = response.content.decode('utf-8')
            except UnicodeDecodeError:
                body = "Binary or non-UTF-8 content"

            if body is not None:
                logger.info(f"Response Body: {body}")

        # Call Celery task to store API request
        try:
            store_api_req_task(request, response)
        except Exception as e:
            logger.error(f"Error calling Celery task: {e}")
