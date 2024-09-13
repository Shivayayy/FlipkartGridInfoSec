import logging
import re
from django.http import JsonResponse, HttpResponse
from pymongo import MongoClient
import os
from dotenv import load_dotenv
import hashlib
import requests

logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()

# Initialize MongoDB client and collection using environment variables
mongodb_uri = os.getenv('MONGODB_URI')
client = MongoClient(mongodb_uri)
db = client.get_default_database()  # Use the default database if not specified in the URI
api_reports = db['owaspReqScanner']
middle = db['middle']


class ResourceAccessMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        attack_detected = False  # Flag to track attack detection

        user = request.headers.get('X-User')
        resource = request.headers.get('X-Resource')

        if user and resource:
            user_resource_entries = list(middle.find({'X-key': 'user-resource'}))

            user_resource_map = {}
            for entry in user_resource_entries:
                try:
                    user_val, resource_val = entry['X-value'].split(':')
                    user_resource_map[user_val] = resource_val
                except ValueError:
                    continue  # Skip malformed entries

            if user in user_resource_map:
                if user_resource_map[user] != resource:
                    api_reports.insert_one({
                        'status': 400,
                        'message': "Access Denied: You don't have access to this resource.",
                        'OWASP_id': "A01",
                        'OWASP_category': "Broken Access Control",
                        'headers': {
                            'X-User': user,
                            'X-Resource': resource,
                        },
                        'api_endpoint': request.path,
                    })
                    attack_detected = True
            else:
                api_reports.insert_one({
                    'status': 400,
                    'message': "Access Denied: Invalid user.",
                    'OWASP_id': "A01",
                    'OWASP_category': "Broken Access Control",
                    'headers': {
                        'X-User': user,
                        'X-Resource': resource,
                    },
                    'api_endpoint': request.path,
                })
                attack_detected = True

        insecure_algorithms = [entry['X-value'] for entry in middle.find({'X-key': 'X-Cryptographic-Algorithm'})]

        insecure_key_lengths = {}
        for entry in middle.find({'X-key': 'X-Cryptographic-Key-Length'}):
            algorithm = entry.get('algorithm')
            key_length = entry.get('X-value')
            if algorithm and key_length:
                insecure_key_lengths[algorithm] = int(key_length)

        algorithm = request.headers.get('X-Cryptographic-Algorithm')
        key_length = request.headers.get('X-Cryptographic-Key-Length')

        if algorithm and algorithm in insecure_algorithms:
            api_reports.insert_one({
                'status': 400,
                'message': "Insecure cryptographic algorithm detected!",
                'OWASP_id': "A02",
                'OWASP_category': "Cryptographic failures",
                'headers': {
                    'X-Cryptographic-Algorithm': algorithm,
                },
                'api_endpoint': request.path,
            })
            attack_detected = True

        if algorithm and key_length:
            try:
                key_length_int = int(key_length)
                if key_length_int == insecure_key_lengths.get(algorithm, 0):
                    api_reports.insert_one({
                        'status': 400,
                        'message': "Insecure key length detected!",
                        'OWASP_id': "A02",
                        'OWASP_category': "Cryptographic failures",
                        'headers': {
                            'X-Cryptographic-Algorithm': algorithm,
                            'X-Cryptographic-Key-Length': key_length,
                        },
                        'api_endpoint': request.path,
                    })
                    attack_detected = True
            except ValueError:
                # Invalid key_length value
                api_reports.insert_one({
                    'status': 400,
                    'message': "Invalid cryptographic key length format.",
                    'OWASP_id': "A02",
                    'OWASP_category': "Cryptographic failures",
                    'headers': {
                        'X-Cryptographic-Key-Length': key_length,
                    },
                    'api_endpoint': request.path,
                })
                attack_detected = True

        if request.path.startswith('/api') and request.method == 'POST':
            try:
                request_body = request.body.decode('utf-8')
            except UnicodeDecodeError:
                request_body = ''

            # SQL Injection patterns
            sql_injection_patterns = [r'union|select|insert|update|delete|drop', r'--']
            for pattern in sql_injection_patterns:
                if re.search(pattern, request_body, re.IGNORECASE):
                    api_reports.insert_one({
                        'status': 400,
                        'message': "Potential SQL Injection detected!",
                        'OWASP_id': "A03",
                        'OWASP_category': "Injection",
                        'api_endpoint': request.path,
                    })
                    attack_detected = True
                    break  # Avoid multiple logs for the same type

            # XSS patterns
            xss_patterns = [r'<script>', r'</script>', r'onerror=', r'onload=', r'javascript:']
            for pattern in xss_patterns:
                if re.search(pattern, request_body, re.IGNORECASE):
                    api_reports.insert_one({
                        'status': 400,
                        'message': "Potential XSS detected!",
                        'OWASP_id': "A03",
                        'OWASP_category': "Injection",
                        'api_endpoint': request.path,
                    })
                    attack_detected = True
                    break

            # Command Injection patterns
            command_injection_patterns = [r';', r'&&', r'\|\|']
            for pattern in command_injection_patterns:
                if re.search(pattern, request_body, re.IGNORECASE):
                    api_reports.insert_one({
                        'status': 400,
                        'message': "Potential Command Injection detected!",
                        'OWASP_id': "A03",
                        'OWASP_category': "Injection",
                        'api_endpoint': request.path,
                    })
                    attack_detected = True
                    break

            # LDAP Injection patterns
            ldap_injection_patterns = [r'[\(\)\*\&\|]', r'\\']
            for pattern in ldap_injection_patterns:
                if re.search(pattern, request_body, re.IGNORECASE):
                    api_reports.insert_one({
                        'status': 400,
                        'message': "Potential LDAP Injection detected!",
                        'OWASP_id': "A03",
                        'OWASP_category': "Injection",
                        'api_endpoint': request.path,
                    })
                    attack_detected = True
                    break

        feedback = request.headers.get('X-Feedback')
        if feedback:
            if re.search(r'<script.*?>.*?</script>', feedback, re.IGNORECASE):
                api_reports.insert_one({
                    'status': 400,
                    'message': "Potential XSS detected in feedback!",
                    'OWASP_id': "A04",
                    'OWASP_category': "Insecure Design",
                    'headers': {
                        'X-Feedback': feedback,
                    },
                    'api_endpoint': request.path,
                })
                attack_detected = True

        xss_check = request.headers.get('X-Comment')
        if xss_check:
            if re.search(r'<script.*?>.*?</script>', xss_check, re.IGNORECASE):
                api_reports.insert_one({
                    'status': 400,
                    'message': "Potential XSS detected in comment!",
                    'OWASP_id': "A04",
                    'OWASP_category': "Insecure Design",
                    'headers': {
                        'X-Comment': xss_check,
                    },
                    'api_endpoint': request.path,

                })
                attack_detected = True

        supported_algorithms = [entry['X-value'].lower() for entry in
                                middle.find({'X-key': 'Supported-Crypto-Algorithm'})]

        crypto_algo = request.headers.get('X-Cryptographic-Algorithm')
        if crypto_algo and crypto_algo.lower() not in supported_algorithms:
            api_reports.insert_one({
                'status': 400,
                'message': "Unsupported cryptographic algorithm detected!",
                'OWASP_id': "A04",
                'OWASP_category': "Insecure Design",
                'headers': {
                    'X-Cryptographic-Algorithm': crypto_algo,
                },
                'api_endpoint': request.path,
            })
            attack_detected = True

        token_matches = list(middle.find({'X-key': 'X-Credentials'}))

        credentials = request.headers.get('X-Credentials')
        match_found = False
        if credentials:
            for token in token_matches:
                if credentials == token.get('X-value'):
                    match_found = True
                    break

            if match_found:
                api_reports.insert_one({
                    'status': 400,
                    'message': "Security Misconfiguration: Default credentials detected!",
                    'OWASP_id': "A05",
                    'OWASP_category': "Security Misconfiguration",
                    'headers': {
                        'X-Credentials': credentials,
                    },
                    'api_endpoint': request.path,
                })
                attack_detected = True

        error_simulation = request.headers.get('X-Simulate-Error')
        services = request.headers.get('X-Services')
        permissions = request.headers.get('X-Permissions')
        xxe_check = request.headers.get('X-XXE')
        component_version = request.headers.get('X-Component-Version')

        if error_simulation:
            db_values = list(middle.find({'X-key': 'X-Simulate-Error'}))
            for db_value in db_values:
                if db_value.get('X-value') == error_simulation:
                    api_reports.insert_one({
                        'status': 500,
                        'message': "Verbose error message simulation: SQL Error: ERROR: relation \"users\" does not exist",
                        'OWASP_id': "A05",
                        'OWASP_category': "Security Misconfiguration",
                        'headers': {
                            'X-Simulate-Error': error_simulation,
                        },
                        'api_endpoint': request.path,
                    })
                    attack_detected = True
                    break

        if services:
            db_values = list(middle.find({'X-key': 'X-Services'}))
            for db_value in db_values:
                if db_value.get('X-value') in services:
                    api_reports.insert_one({
                        'status': 400,
                        'message': "Security Misconfiguration: Unnecessary service detected!",
                        'OWASP_id': "A05",
                        'OWASP_category': "Security Misconfiguration",
                        'headers': {
                            'X-Services': services,
                        },
                        'api_endpoint': request.path,
                    })
                    attack_detected = True
                    break

        if permissions:
            db_values = list(middle.find({'X-key': 'X-Permissions'}))
            for db_value in db_values:
                if db_value.get('X-value') == permissions:
                    api_reports.insert_one({
                        'status': 400,
                        'message': "Security Misconfiguration: Improper file permissions detected!",
                        'OWASP_id': "A05",
                        'OWASP_category': "Security Misconfiguration",
                        'headers': {
                            'X-Permissions': permissions,
                        },
                        'api_endpoint': request.path,
                    })
                    attack_detected = True
                    break

        if xxe_check:
            db_values = list(middle.find({'X-key': 'X-XXE'}))
            for db_value in db_values:
                if db_value.get('X-value') == xxe_check:
                    api_reports.insert_one({
                        'status': 400,
                        'message': "Security Misconfiguration: Potential XXE vulnerability detected!",
                        'OWASP_id': "A05",
                        'OWASP_category': "Security Misconfiguration",
                        'headers': {
                            'X-XXE': xxe_check,
                        },
                        'api_endpoint': request.path,
                    })
                    attack_detected = True
                    break

        if component_version:
            db_values = list(middle.find({'X-key': 'X-Component-Version'}))
            for db_value in db_values:
                if db_value.get('X-value') == component_version:
                    message = "Vulnerable Component: Outdated component version detected!"
                    if component_version == "2.0.0":
                        message = "Vulnerable Component: Known vulnerability in version 2.0.0!"

                    api_reports.insert_one({
                        'status': 400,
                        'message': message,
                        'OWASP_id': "A06",
                        'OWASP_category': "Vulnerable and Outdated Components",
                        'headers': {
                            'X-Component-Version': component_version,
                        },
                        'api_endpoint': request.path,
                    })
                    attack_detected = True
                    break

        auth_token = request.headers.get('Authorization-Token')
        username = request.headers.get('Username')

        valid_auth_tokens = list(middle.find({'X-key': 'Authorization-Token'}))
        valid_usernames = list(middle.find({'X-key': 'Username'}))

        valid_auth_token_values = [entry.get('X-value') for entry in valid_auth_tokens]
        valid_username_values = [entry.get('X-value') for entry in valid_usernames]

        if auth_token and auth_token not in valid_auth_token_values:
            api_reports.insert_one({
                'status': 403,
                'message': "Error: Invalid authentication token.",
                'OWASP_id': "A07",
                'OWASP_category': "Identification and Authentication failures",
                'headers': {
                    'Authorization-Token': auth_token,
                    'Username': username,
                },
                'api_endpoint': request.path,
            })
            attack_detected = True

        if username and username not in valid_username_values:
            api_reports.insert_one({
                'status': 403,
                'message': "Error: Invalid username.",
                'OWASP_id': "A07",
                'OWASP_category': "Identification and Authentication failures",
                'headers': {
                    'Username': username,
                },
                'api_endpoint': request.path,
            })
            attack_detected = True

        integrity_check_header = request.headers.get('X-Integrity-Check')
        data_integrity_header = request.headers.get('X-Data-Integrity')
        update_url_header = request.headers.get('X-Update-URL')

        update_url_entries = list(middle.find({'X-key': 'Update-URL-Hash'}))
        data_integrity_entries = list(middle.find({'X-key': 'Data-Integrity-Hash'}))
        integrity_check_entries = list(middle.find({'X-key': 'Integrity-Check-Hash'}))

        expected_update_url_hashes = [entry.get('X-value') for entry in update_url_entries]
        expected_data_integrity_hashes = [entry.get('X-value') for entry in data_integrity_entries]
        valid_integrity_hashes = [entry.get('X-value') for entry in integrity_check_entries]

        if update_url_header:
            try:
                update_response = requests.get(update_url_header)
                downloaded_hash = hashlib.sha256(update_response.content).hexdigest()

                if downloaded_hash in expected_update_url_hashes:
                    logger.warning("Software update integrity check failed.")
                    api_reports.insert_one({
                        'status': 400,
                        'message': "Error: Software update integrity check failed.",
                        'OWASP_id': "A08",
                        'OWASP_category': "Software and Data Integrity failures",
                        'headers': {
                            'X-Update-URL': update_url_header,
                        },
                        'api_endpoint': request.path,
                    })
                    attack_detected = True
            except requests.RequestException:
                # Handle request errors (e.g., network issues)
                api_reports.insert_one({
                    'status': 400,
                    'message': "Error: Failed to perform software update integrity check.",
                    'OWASP_id': "A08",
                    'OWASP_category': "Software and Data Integrity failures",
                    'headers': {
                        'X-Update-URL': update_url_header,
                    },
                    'api_endpoint': request.path,
                })
                attack_detected = True

        if data_integrity_header:
            if data_integrity_header in expected_data_integrity_hashes:
                logger.warning("Data integrity check failed.")
                api_reports.insert_one({
                    'status': 400,
                    'message': "Error: Data integrity check failed.",
                    'OWASP_id': "A08",
                    'OWASP_category': "Software and Data Integrity failures",
                    'headers': {
                        'X-Data-Integrity': data_integrity_header,
                    },
                    'api_endpoint': request.path,
                })
                attack_detected = True

        if integrity_check_header:
            if integrity_check_header in valid_integrity_hashes:
                logger.warning("General integrity check failed.")
                api_reports.insert_one({
                    'status': 400,
                    'message': "Error: General integrity check failed.",
                    'OWASP_id': "A08",
                    'OWASP_category': "Software and Data Integrity failures",
                    'headers': {
                        'X-Integrity-Check': integrity_check_header,
                    },
                    'api_endpoint': request.path,
                })
                attack_detected = True

        if not logger.hasHandlers():
            print("Logger is not configured properly or has no handlers.")
            api_reports.insert_one({
                'status': 500,
                'message': "Error: Logger not configured properly.",
                'OWASP_id': "A09",
                'OWASP_category': "Security Logging and Monitoring failures",
                'api_endpoint': request.path,
            })
            attack_detected = True

        logger.info("Logger is working correctly.")

        ssrf_test = request.headers.get('X-SSRF-Test')

        if ssrf_test:
            db_values = list(middle.find({'X-key': 'X-SSRF-Test'}))
            for db_value in db_values:
                if db_value.get('X-value') in ssrf_test:
                    api_reports.insert_one({
                        'status': 400,
                        'message': "Error: Attempted SSRF attack detected.",
                        'OWASP_id': "A10",
                        'OWASP_category': "Server Side Request Forgery",
                        'headers': {
                            'X-SSRF-Test': ssrf_test,
                        },
                        'api_endpoint': request.path,
                    })
                    attack_detected = True
                    break

        if attack_detected:
            # Optionally, you can include more detailed information in the response
            # or keep it generic as per your requirement.
            return JsonResponse({'results': "Bad request ,attack detected", 'status': "OK"}, safe=False)

        # No attack detected, proceed with the request.
        response = self.get_response(request)
        return response

    '''
    To handle version management and detection of vulnerabilities more dynamically, you can implement a solution that involves:

    -> Maintaining a Version Repository: Keep a record of the current, secure versions of components used in your application. This can be  
       a database, configuration file, or a remote service.

    -> Fetching and Comparing Versions: Implement middleware that compares the version provided in the request against the version in your 
       repository.

    '''
