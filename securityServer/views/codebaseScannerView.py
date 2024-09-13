from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from ..DataBaseAccess.api_inventory_service import update_api_inventory_task
import os
from github import Github
import re
import logging
from dotenv import load_dotenv
from transformers import AutoModelForSeq2SeqLM, AutoTokenizer

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class ExtractAPIEndpoints(APIView):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Load the model and tokenizer
        model_name = "Salesforce/codet5-base"
        self.model = AutoModelForSeq2SeqLM.from_pretrained(model_name)
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.mount_paths = {}
        print("Initialized model and tokenizer")

    def get_github_files(self):
        github_token = os.getenv('GITHUB_TOKEN')
        if not github_token:
            raise ValueError("GITHUB_TOKEN environment variable not set")

        # Debug print to ensure token is loaded
        print("GitHub Token:", github_token)

        repo_name = "p-rohitt/org-backend"
        g = Github(github_token)
        try:
            repo = g.get_repo(repo_name)
        except Exception as e:
            logger.error(f"GitHub API error: {str(e)}")
            raise

        contents = repo.get_contents("")
        code_files = []

        while contents:
            file_content = contents.pop(0)
            if file_content.type == "dir":
                contents.extend(repo.get_contents(file_content.path))
            else:
                if file_content.name.endswith((".py", ".js", ".java", ".cpp", ".ts")):
                    code_files.append({
                        "path": file_content.path,
                        "content": file_content.decoded_content.decode()
                    })
                    logger.debug(f"Fetched file: {file_content.path}")

        if not code_files:
            print("No code files found")
        return code_files

    def parse_mount_paths(self, code_files):
        mount_pattern = r'app\.use\([\'"]([^\'"]+)[\'"]\s*,\s*(\w+)\)'
        for file in code_files:
            if file['path'].endswith(('index.js', 'app.js')):
                matches = re.findall(mount_pattern, file['content'])
                for match in matches:
                    base_path, router_name = match
                    self.mount_paths[router_name] = base_path

    def get_full_path(self, file_path, endpoint):
        for router_name, base_path in self.mount_paths.items():
            if router_name.lower() in file_path.lower():
                if "admin" in file_path.lower():
                    return f"/api/admin{endpoint}"
                return f"{base_path.rstrip('/')}/{endpoint.lstrip('/')}"
        return endpoint

    def extract_api_endpoints(self, code_files):
        endpoints = []
        # Patterns to match API routes
        route_patterns = [
            r'router\.get\([\'"]([^\'"]+)[\'"]',
            r'router\.post\([\'"]([^\'"]+)[\'"]',
            r'router\.put\([\'"]([^\'"]+)[\'"]',
            r'router\.delete\([\'"]([^\'"]+)[\'"]',
            r'app\.get\([\'"]([^\'"]+)[\'"]',
            r'app\.post\([\'"]([^\'"]+)[\'"]',
            r'app\.put\([\'"]([^\'"]+)[\'"]',
            r'app\.delete\([\'"]([^\'"]+)[\'"]',
            r'^[\s]*@app\.get\([\'"]([^\'"]+)[\'"]',
            r'^[\s]*@app\.post\([\'"]([^\'"]+)[\'"]',
            r'^[\s]*@app\.put\([\'"]([^\'"]+)[\'"]',
            r'^[\s]*@app\.delete\([\'"]([^\'"]+)[\'"]',
            r'^[\s]*router\.use\([\'"]([^\'"]+)[\'"]'
        ]

        for code in code_files:
            try:
                file_content = code["content"]
                file_path = code["path"]
                if file_content:
                    logger.debug(f"Processing file: {file_path}")

                    for pattern in route_patterns:
                        matches = re.findall(pattern, file_content)
                        for match in matches:
                            method = pattern.split('.')[1].split('(')[0].upper().strip('\\')
                            full_path = self.get_full_path(file_path, match)
                            endpoints.append({
                                "file": file_path,
                                "method": method,
                                "endpoint": match,
                                "full_path": full_path
                            })
                            update_api_inventory_task.delay(method, full_path)
                            logger.debug(f"Match found: {method} {full_path}")
                else:
                    logger.debug(f"No content for file: {file_path}")
            except Exception as e:
                # Ensure file_path is defined before referencing
                file_path = code.get("path", "Unknown file path")
                logger.error(f"Error processing file {file_path}: {str(e)}")
                continue

        if not endpoints:
            print("No API endpoints extracted")
        return endpoints

    def get(self, request):
        try:
            print("Starting GET request handling")
            code_files = self.get_github_files()
            if not code_files:
                logger.info("No code files found.")
                print("No code files found.")
                return Response({"api_endpoints": []}, status=status.HTTP_200_OK)

            self.parse_mount_paths(code_files)
            api_endpoints = self.extract_api_endpoints(code_files)
            logger.info(f"Extracted API endpoints: {api_endpoints}")
            print(f"Extracted API endpoints: {api_endpoints}")
            return Response({"api_endpoints": "ok"}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error during API extraction: {str(e)}")
            print(f"Error during API extraction: {str(e)}")
            return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
