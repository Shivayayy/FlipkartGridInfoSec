from django.views import View
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
import requests
import time
import logging
import os
from dotenv import load_dotenv
from pymongo import MongoClient
from django.conf import settings

# Load environment variables from .env file
load_dotenv()

# Utility imports
from ..DataBaseAccess.api_inventory_service import update_api_inventory_task
from ..DataBaseAccess.fetch_unique_endpoints import fetch_unique_endpoints
from ..DataBaseAccess.store_scan_reports import store_scan_report_task
from ..utility.convert_risk_to_score import convert_risk_to_score
from ..utility.determine_risk_factor import determine_risk_factor
from ..utility.report_ticket_generator import get_and_store_tickets
logger = logging.getLogger(__name__)



# Initialize MongoDB client
mongodb_uri = getattr(settings, 'MONGODB_URI', None)
if mongodb_uri is None:
    logger.error("MONGODB_URI setting not found")
    raise ValueError("MONGODB_URI setting not found")

client = MongoClient(mongodb_uri)
db = client.get_default_database()
notification_collection = db['notifications']

class spiderTest(View):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.zap_base_url = os.getenv('ZAP_BASE_URL', 'http://localhost:8080')
        self.zap_api_key = os.getenv('ZAP_API_KEY', '')

    @method_decorator(csrf_exempt)
    def get(self, request):

        scan_report ={
    "https://flipkart-rose-six.vercel.app/api/hello": {
      "alerts": [
        {
          "sourceid": "3",
          "method": "GET",
          "evidence": "public, max-age=0, must-revalidate",
          "pluginId": "10015",
          "cweid": "525",
          "confidence": "Low",
          "wascid": "13",
          "description": "The cache-control header has not been set properly or is missing, allowing the browser and proxies to cache content. For static assets like css, js, or image files this might be intended, however, the resources should be reviewed to ensure that no sensitive content will be cached.",
          "messageId": "7",
          "inputVector": "",
          "url": "https://flipkart-rose-six.vercel.app/api/hello",
          "tags": {
            "CWE-525": "https://cwe.mitre.org/data/definitions/525.html",
            "WSTG-v42-ATHN-06": "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_Browser_Cache_Weaknesses"
          },
          "reference": "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#web-content-caching\nhttps://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control\nhttps://grayduck.mn/2021/09/13/cache-control-recommendations/",
          "solution": "For secure content, ensure the cache-control HTTP header is set with \"no-cache, no-store, must-revalidate\". If an asset should be cached consider setting the directives \"public, max-age, immutable\".",
          "alert": "Re-examine Cache-control Directives",
          "param": "cache-control",
          "attack": "",
          "name": "Re-examine Cache-control Directives",
          "risk": "Informational",
          "risk_score": 1,
          "id": "0",
          "alertRef": "10015"
        },
        {
          "sourceid": "3",
          "method": "GET",
          "evidence": "Age: 0",
          "pluginId": "10050",
          "cweid": "-1",
          "confidence": "Medium",
          "wascid": "-1",
          "description": "The content was retrieved from a shared cache. If the response data is sensitive, personal or user-specific, this may result in sensitive information being leaked. In some cases, this may even result in a user gaining complete control of the session of another user, depending on the configuration of the caching components in use in their environment. This is primarily an issue where caching servers such as \"proxy\" caches are configured on the local network. This configuration is typically found in corporate or educational environments, for instance. ",
          "messageId": "7",
          "inputVector": "",
          "url": "https://flipkart-rose-six.vercel.app/api/hello",
          "tags": {
            "WSTG-v42-ATHN-06": "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_Browser_Cache_Weaknesses"
          },
          "reference": "https://tools.ietf.org/html/rfc7234\nhttps://tools.ietf.org/html/rfc7231\nhttps://www.rfc-editor.org/rfc/rfc9110.html",
          "solution": "Validate that the response does not contain sensitive, personal or user-specific information.  If it does, consider the use of the following HTTP response headers, to limit, or prevent the content being stored and retrieved from the cache by another user:\nCache-Control: no-cache, no-store, must-revalidate, private\nPragma: no-cache\nExpires: 0\nThis configuration directs both HTTP 1.0 and HTTP 1.1 compliant caching servers to not store the response, and to not retrieve the response (without validation) from the cache, in response to a similar request.",
          "alert": "Retrieved from Cache",
          "param": "",
          "attack": "",
          "name": "Retrieved from Cache",
          "risk": "Informational",
          "risk_score": 1,
          "id": "1",
          "alertRef": "10050-2"
        },
        {
          "sourceid": "3",
          "method": "GET",
          "evidence": "",
          "pluginId": "10021",
          "cweid": "693",
          "confidence": "Medium",
          "wascid": "15",
          "description": "The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.",
          "messageId": "7",
          "inputVector": "",
          "url": "https://flipkart-rose-six.vercel.app/api/hello",
          "tags": {
            "OWASP_2021_A05": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
            "CWE-693": "https://cwe.mitre.org/data/definitions/693.html",
            "OWASP_2017_A06": "https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration.html"
          },
          "reference": "https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/compatibility/gg622941(v=vs.85)\nhttps://owasp.org/www-community/Security_Headers",
          "solution": "Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.\nIf possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.",
          "alert": "X-Content-Type-Options Header Missing",
          "param": "x-content-type-options",
          "attack": "",
          "name": "X-Content-Type-Options Header Missing",
          "risk": "Low",
          "risk_score": 2,
          "id": "2",
          "alertRef": "10021"
        },
        {
          "sourceid": "3",
          "method": "GET",
          "evidence": "X-Powered-By: Express",
          "pluginId": "10037",
          "cweid": "200",
          "confidence": "Medium",
          "wascid": "13",
          "description": "The web/application server is leaking information via one or more \"X-Powered-By\" HTTP response headers. Access to such information may facilitate attackers identifying other frameworks/components your web application is reliant upon and the vulnerabilities such components may be subject to.",
          "messageId": "7",
          "inputVector": "",
          "url": "https://flipkart-rose-six.vercel.app/api/hello",
          "tags": {
            "OWASP_2021_A01": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
            "WSTG-v42-INFO-08": "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework",
            "OWASP_2017_A03": "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure.html",
            "CWE-200": "https://cwe.mitre.org/data/definitions/200.html"
          },
          "reference": "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework\nhttps://www.troyhunt.com/2012/02/shhh-dont-let-your-response-headers.html",
          "solution": "Ensure that your web server, application server, load balancer, etc. is configured to suppress \"X-Powered-By\" headers.",
          "alert": "Server Leaks Information via \"X-Powered-By\" HTTP Response Header Field(s)",
          "param": "",
          "attack": "",
          "name": "Server Leaks Information via \"X-Powered-By\" HTTP Response Header Field(s)",
          "risk": "Low",
          "risk_score": 2,
          "id": "3",
          "alertRef": "10037"
        }
      ]
    }
  }

        if scan_report:
            ticket_ids = get_and_store_tickets(scan_report)  # Retrieve all ticket IDs
            report_result = store_scan_report_task.delay(scan_report,ticket_ids)

            report_id = report_result.id
            notification_data = {
                'notification_code': '5',
                'tag': 'manual_scan_triggered',
                'message': 'Dynamic Scanning for latest scan completed. Tap to view report',
                'report_id': report_id
            }
            notification_collection.insert_one(notification_data)
        return JsonResponse({'results': "report_result", 'status': "OK"}, safe=False)



