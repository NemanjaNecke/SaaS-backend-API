from django.urls import path, include
from rest_framework import routers
from dj_rest_auth.registration.views import VerifyEmailView, ConfirmEmailView
from .views import ResendEmailVerificationView

urlpatterns = [
    path(
        r'auth/registration/account-confirm-email/<str:key>/',
        ConfirmEmailView.as_view(),
    ),
    path('auth/registration/resend-email/', ResendEmailVerificationView.as_view(),
         name="rest_resend_email"),
    path(r'auth/', include('dj_rest_auth.urls')),   
    path(r'auth/registration/', include('dj_rest_auth.registration.urls')),
    path(
        'auth/account-confirm-email/',
        VerifyEmailView.as_view(),
        name='account_email_verification_sent'
    ),
]