# apiSecurityShield/urls.py
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path('admin/', admin.site.urls),
    path('data/', include('data.urls')),
    path('tickets/', include('tickets.urls')),
    path('users/', include('user.urls')),
    path('', include('securityServer.urls')),

]

