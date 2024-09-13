from django.urls import path, re_path

from .regressionSuites.dynamicRegression import DynamicRegression
from .views.codebaseScannerView import ExtractAPIEndpoints
from .views.spiderScanView import SpiderScanView
from .views.proxyView import proxy_view
from .views.homeView import home_view
from .views.vulnerabiltyScannerView import scan_api_view
from .views.bearerScanView import BearerScanView
from .views.nuclieScanView import NucleiScanView
from .views.scanSingle import SingleEndpointScanView
from .views.alertSystem import handle_notification_update
from .views.getAllNotification import fetch_notifications_view
from .regressionSuites.dynamicRegression import DynamicRegression
from .regressionSuites.staticRegression import StaticRegression
from .views.noSpideringTest import spiderTest
from .views.realTimeMonitoring import get_requests_per_second

urlpatterns = [
    path('', home_view, name='home'),
    path('extract/', ExtractAPIEndpoints.as_view(), name='extract_api_endpoints'),
    path('realTime/',get_requests_per_second,name ='per_second_request_scanner'),
    path('scan/', SpiderScanView.as_view(), name='spider_scan'),
    path('scanSingle/',SingleEndpointScanView.as_view(), name='scan-endpoint'),
    path('vulnerabilityScan/' ,scan_api_view, name ="vulnerabilty_scanner"),
    path('bearerScan/', BearerScanView.as_view(), name='bearer_scan'),
    path('nuclieScan/',NucleiScanView.as_view(),name ='nuclie_scan'),
    path('test/dynamicTesting/' ,DynamicRegression.as_view() ,name ='dynamic_testing'),
    path('test/staticTesting/' ,StaticRegression.as_view() ,name ='static_testing'),
    path('notification/update/', handle_notification_update, name='handle_notification_update'),
    path('notification/all/' , fetch_notifications_view, name ='get_all_notification'),
    path('mockSpider/',spiderTest.as_view(),name = 'mock_spider_test'),
    path('<path:path>', proxy_view, name='proxy_view')
]
