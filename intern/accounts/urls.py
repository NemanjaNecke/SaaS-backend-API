from django.urls import path, include
from rest_framework import routers
from dj_rest_auth.registration.views import VerifyEmailView, ConfirmEmailView

urlpatterns = [
    path(
        r'auth/registration/account-confirm-email/<str:key>/',
        ConfirmEmailView.as_view(),
    ), 
    path(r'auth/', include('dj_rest_auth.urls')),   
    path(r'auth/registration/', include('dj_rest_auth.registration.urls')),
    path(
        'auth/account-confirm-email/',
        VerifyEmailView.as_view(),
        name='account_email_verification_sent'
    ),
]