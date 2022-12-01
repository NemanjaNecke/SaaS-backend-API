from django.urls import path, include
from rest_framework import routers

urlpatterns = [
    path(r'auth/', include('dj_rest_auth.urls')),
    path(r'auth/registration', include('dj_rest_auth.registration.urls'))
]