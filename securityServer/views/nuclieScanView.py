import subprocess
import json
import os
import logging
from django.http import JsonResponse
from django.views import View
from pymongo import MongoClient

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize MongoDB client and collection using environment variables
mongodb_uri = os.getenv('MONGODB_URI')
if mongodb_uri is None:
    raise ValueError("MONGODB_URI environment variable not set")

client = MongoClient(mongodb_uri)
db = client.get_default_database()  # Use the default database if not specified in the URI
api_inventory_collection = db['apiEndpointInventory']


def fetch_unique_endpoints():
    """Fetch unique API endpoints from MongoDB."""
    logger.info("Fetching unique endpoints from MongoDB.")
    return api_inventory_collection.distinct('path')


def scan_endpoint(base_url, path):
    """Run Nuclei scan for the given endpoint."""
    url = f"{base_url}{path}"
    logger.info(f"Scanning endpoint: {url}")
    try:
        # Run Nuclei with dynamic scanning
        result = subprocess.run(
            ["nuclei", "-u", url],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            logger.error(f"Failed to scan {url}")
            return {"error": f"Failed to scan {url}"}

        scan_report = json.loads(result.stdout)
        logger.info(f"Scan completed for {url}")
        return scan_report
    except Exception as e:
        logger.error(f"Error scanning {url}: {str(e)}")
        return {"error": str(e)}


class NucleiScanView(View):
    def get(self, request):
        base_url = 'https://onlineshop-psi-seven.vercel.app'
        results = []

        logger.info("Starting Nuclei scan for all endpoints.")

        try:
            # Fetch unique endpoints from MongoDB
            unique_endpoints = fetch_unique_endpoints()

            if not unique_endpoints:
                logger.warning("No endpoints found in MongoDB.")

            for path in unique_endpoints:
                logger.info(f"Scanning endpoint path: {path}")
                scan_result = scan_endpoint(base_url, path)
                results.append({"endpoint": path, "scan_result": scan_result})

            logger.info("Nuclei scan completed for all endpoints.")
            return JsonResponse({"scan_results": results}, safe=False)

        except Exception as e:
            logger.error(f"Error during Nuclei scan: {str(e)}")
            return JsonResponse({"error": str(e)}, status=500)
