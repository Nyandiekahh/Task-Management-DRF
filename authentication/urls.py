# authentication/urls.py
from django.urls import path
from rest_framework.routers import DefaultRouter
from .views import (
    LoginView,
    UserViewSet,
    RoleViewSet,
    PermissionViewSet,
)

router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')
router.register(r'roles', RoleViewSet)
router.register(r'permissions', PermissionViewSet)

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
] + router.urls