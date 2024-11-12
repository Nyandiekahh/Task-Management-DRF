# backend/urls.py
from django.contrib import admin
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from authentication.views import TaskViewSet, ActivityLogViewSet

# Create a router for non-auth endpoints
api_router = DefaultRouter()
api_router.register(r'tasks', TaskViewSet, basename='task')
api_router.register(r'activity-logs', ActivityLogViewSet, basename='activity-log')

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/auth/', include('authentication.urls')),
    path('api/', include(api_router.urls)),
]