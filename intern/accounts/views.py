from django.shortcuts import render
from rest_framework import generics
from dj_rest_auth.registration.serializers import ResendEmailVerificationSerializer
from rest_framework import status
from django.utils.translation import gettext_lazy as _
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from allauth.account.models import EmailAddress
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import  force_str
from .adapter import account_activation_token
from rest_framework.decorators import api_view, renderer_classes
from rest_framework.renderers import JSONRenderer
from .models import IPAddress, Account
import time

class ResendEmailVerificationView(generics.CreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = ResendEmailVerificationSerializer
    queryset = EmailAddress.objects.all()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = EmailAddress.objects.filter(**serializer.validated_data).first()
        if email: 
            if not email.verified:
                email.send_confirmation(request)
            else:
                return Response({_('Email already verified')}, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        else:
            return Response({_('Email not found')}, status=status.HTTP_404_NOT_FOUND)
        return Response({'detail': _('ok')}, status=status.HTTP_200_OK)

@api_view(('GET',))
@renderer_classes((JSONRenderer,))
def activate(request, uidb64, token):
    uid = force_str(urlsafe_base64_decode(uidb64)).split('-')

    ip_address = {"ip_address": uid[1], "verified": True}
    ip_address = IPAddress.objects.create(
        account=Account.objects.get(email=uid[0]), **ip_address)

    if account_activation_token.check_token(uid[0], token):

        return Response({'detail': _('IP address verified successfully')}, status=status.HTTP_200_OK)
        
    else:
        return Response({_('Activation link not valid')}, status=status.HTTP_404_NOT_FOUND)