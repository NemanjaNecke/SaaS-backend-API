from django.urls import path, include
from rest_framework import routers
from dj_rest_auth.registration.views import VerifyEmailView, ConfirmEmailView
from .views import ResendEmailVerificationView, activate
from dj_rest_auth.views import PasswordResetConfirmView


urlpatterns = [
    path(
        r'auth/registration/account-confirm-email/<str:key>/',
        ConfirmEmailView.as_view(),
    ),
    path('auth/activate-ip/<uidb64>/<token>', activate, name='activate-ip'),
    path(
        'auth/password/reset/confirm/<slug:uidb64>/<slug:token>/',
        PasswordResetConfirmView.as_view(), name='password_reset_confirm'
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
