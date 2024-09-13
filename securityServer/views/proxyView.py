from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
import requests

@csrf_exempt
def proxy_view(request, path):
    target_url = f'https://onlineshop-psi-seven.vercel.app/{path}'
    method = request.method.lower()
    data = request.POST if method == 'post' else request.GET

    headers = {key: value for key, value in request.headers.items()
               if key.lower() not in ['host', 'content-length']}

    response = requests.request(
        method,
        target_url,
        headers=headers,
        data=data,
        cookies=request.COOKIES,
        allow_redirects=False
    )

    proxy_response = HttpResponse(
        response.content,
        status=response.status_code,
        content_type=response.headers.get('Content-Type')
    )

    for key, value in response.headers.items():
        if key.lower() not in ['transfer-encoding', 'content-length']:
            proxy_response[key] = value

    return proxy_response