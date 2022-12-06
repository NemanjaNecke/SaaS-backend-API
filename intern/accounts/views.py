from django.shortcuts import render
from rest_framework import viewsets, generics
from dj_rest_auth.registration.serializers import ResendEmailVerificationSerializer
from rest_framework import status
from django.utils.translation import gettext_lazy as _
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from allauth.account.models import EmailAddress

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
