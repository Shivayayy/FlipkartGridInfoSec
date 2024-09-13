import subprocess
import json
import os
import shutil
import tempfile
from django.http import JsonResponse
from django.views import View
from ..DataBaseAccess.store_bearer_report import store_scan_report

class BearerScanView(View):
    def get(self, request):
        # Hardcoded GitHub repository URL
        github_repo_url = 'https://github.com/p-rohitt/org-backend'
        bearer_executable = os.getenv('BEARER_EXECUTABLE', '/Users/shivamdwivedi/bin/bearer')
        access_token = os.getenv('GITHUB_TOKEN', None)
        # Ensure access token is provided for private repositories
        if not access_token:
            return JsonResponse({"error": "GitHub Access Token not provided."}, status=400)

        # Create a temporary directory for cloning the GitHub repository
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_dir = os.path.join(temp_dir, 'repo')

            try:
                # Clone the repository using access token authentication
                clone_command = [
                    "git", "clone", f"https://{access_token}:x-oauth-basic@{github_repo_url.replace('https://', '')}", repo_dir
                ]
                subprocess.run(clone_command, check=True, capture_output=True, text=True)

                # Run Bearer scan on the cloned repository
                command = [bearer_executable, "scan", ".", "--report", "security", "--format", "json", "--force"]
                result = subprocess.run(command, cwd=repo_dir, capture_output=True, text=True, timeout=600, check=False)

                # Try to parse JSON from stdout first, then stderr if stdout is empty
                output = result.stdout if result.stdout else result.stderr
                scan_data = json.loads(output)

                # Store the scan report in the database
                report_id = store_scan_report(scan_data)

                # Return the scan results with the database ID of the stored report
                response_data = {
                    "scan_data": scan_data,
                    "report_id": report_id
                }
                return JsonResponse(response_data, safe=False)

            except subprocess.CalledProcessError as e:
                return JsonResponse({
                    "error": "Failed to clone repository or run Bearer scan.",
                    "details": str(e),
                    "stderr": e.stderr,
                    "stdout": e.stdout
                }, status=500)
            except subprocess.TimeoutExpired:
                return JsonResponse({"error": "Bearer scan command timed out."}, status=500)
            except json.JSONDecodeError as e:
                return JsonResponse({
                    "error": "Failed to parse JSON output.",
                    "output": output,
                    "details": str(e)
                }, status=500)
            except OSError as e:
                return JsonResponse({"error": "Failed to execute commands.", "details": str(e)}, status=500)
            except Exception as e:
                return JsonResponse({"error": "An unexpected error occurred.", "details": str(e)}, status=500)
