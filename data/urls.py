from django.urls import path
from .views import get_api_reports, api_data_view, unique_endpoints_view,endpoint_info,BearerScanReportView ,StaticSpecific,specific_dynamic_scan_reports,TicketDetailView

urlpatterns = [
    path('dynamicReports/', get_api_reports, name='get_api_reports'),
    path('staticReports/', BearerScanReportView.as_view(), name='scan_reports'),
    path('homeData/', api_data_view, name='api_data_view'),
    path('endpoints/', unique_endpoints_view, name='unique_endpoints_view'),
    path('endpoint-info/', endpoint_info, name='endpoint_info'),
    path('ticketById/',TicketDetailView.as_view(),name='fetch_ticket_by_id'),
    path('staticReportById/' ,StaticSpecific.as_view(),name='static_report_by_id'),
    path('dynamicReportById/' ,specific_dynamic_scan_reports,name ='dynamic_report_by_id')
]
#http://127.0.0.1:8000/data/staticSpecific/?report_id=66d0d3ce08730cdd18af3417

