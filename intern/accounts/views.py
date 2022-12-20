from django.forms import ValidationError
from django.shortcuts import redirect, get_object_or_404
from rest_framework import viewsets, generics, mixins, renderers
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.decorators import action
from allauth.account.models import EmailAddress
from dj_rest_auth.registration.serializers import ResendEmailVerificationSerializer
from rest_framework import status
from django.utils.translation import gettext_lazy as _
from .models import IPAddress, Account, Company, Invitation
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from .adapter import account_activation_token, registration_activation_token
from rest_framework.decorators import api_view, renderer_classes
from rest_framework.renderers import JSONRenderer, TemplateHTMLRenderer
from .serializers import AccountsSerializer, CompanySerializer, IPAddressFullSerializer, InvitationSerializer
from .permissions import IsCompanyAdmin, IsSuperAdmin
from dj_rest_auth.registration.views import RegisterView
from django.views.generic import TemplateView
from allauth.account.utils import complete_signup
from django.conf import settings
from allauth.account import app_settings as allauth_settings
from dj_rest_auth.app_settings import create_token
from dj_rest_auth.utils import jwt_encode
from django.contrib.auth.hashers import make_password

class ResendEmailVerificationView(generics.CreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = ResendEmailVerificationSerializer
    queryset = EmailAddress.objects.all()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = EmailAddress.objects.filter(
            **serializer.validated_data).first()
        if email:
            if not email.verified:
                email.send_confirmation(request)
            else:
                return Response({_('Email already verified')}, 
                status=status.HTTP_503_SERVICE_UNAVAILABLE)
        else:
            return Response({_('Email not found')}, status=status.HTTP_404_NOT_FOUND)
        return Response({'detail': _('ok')}, status=status.HTTP_200_OK)


@api_view(('GET',))
@renderer_classes((JSONRenderer,))
def activate(request, uidb64, token):
    uid = force_str(urlsafe_base64_decode(uidb64)).split('-')
    account = Account.objects.get(email=uid[0])
    ip_address = {"ip_address": uid[1], "verified": True}
    ip_address = IPAddress.objects.create(
        account=account, **ip_address)
    
    if account_activation_token.check_token(uid[0], token):

        return Response({'detail': _('IP address verified successfully')}, status=status.HTTP_200_OK)
    else:
        return Response({_('Activation link not valid')}, status=status.HTTP_404_NOT_FOUND)

    return redirect('homepage')
    return redirect('/login')

class CompanyViewSet(mixins.CreateModelMixin,
                    mixins.ListModelMixin,
                    mixins.RetrieveModelMixin,
                    viewsets.GenericViewSet):
    permission_classes = [IsAuthenticated, IsSuperAdmin]
    serializer_class = CompanySerializer
    queryset = Company.objects.all()
    lookup_field = 'name'
 # napravi create method svoj

    @action(detail=False, methods=['create'])
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        company = serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=['put'], permission_classes=[IsSuperAdmin])
    #dodaj permissions za super admin i handler ako nije
    def deactivate_company(self, request, pk=None, name=None):

        account = request.user    
        company  = get_object_or_404(self.queryset)
        serializer = CompanySerializer(company)

        company.deactivate(account)
        company.save()
        return Response(serializer.data)
    @action(detail=True, methods=['put'], permission_classes=[IsSuperAdmin])
    def activate_company(self, request, pk=None, name=None):
        
        account = request.user    
        company  = get_object_or_404(self.queryset)
        serializer = CompanySerializer(company)

        company.activate(account)
        company.save()
        return Response(serializer.data)

class InvitationViewSet(viewsets.ModelViewSet):
    serializer_class = InvitationSerializer
    queryset = Invitation.objects.all()
    permission_classes = [IsSuperAdmin or IsCompanyAdmin]
    def create(self, request):
        serializer = self.get_serializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        invitation = Invitation(**serializer.validated_data)
        invitation = serializer.save(invitation, request)
        response_data = serializer.data
        response_data.update({'detail': _('Invite sent successfully')})
        return Response(response_data, status=status.HTTP_201_CREATED)

class InviteOnlyRegistrationView(RegisterView):    
    '''
    First, check if the user has accessed the view with a valid invitation link
    This would involve checking the "uid" and "token" parameters in the URL,
    and verifying that they match a valid invitation in the database
    '''
    
    def is_valid_invitation_link(self, request, uid, token):
        uid = force_str(urlsafe_base64_decode(uid)).split('/')
        email = uid[0]
        self.company = uid[1]
        '''
        Check if a valid invitation exists in the database 
        for the given email address and token
        '''
        invitation = Invitation.objects.filter(email=email).first()
        '''Check if token is valid for given user and if the invite exists'''
        if invitation is None or invitation.used ==True or not registration_activation_token.check_token(email, token):
            
            
            return False
        if invitation:
            invitation.accept()
            invitation.save()
        '''If a valid invitation is found, return True'''
        return True

    def dispatch(self, request, *args, **kwargs):

        uid = kwargs.get('uidb64')
        token = kwargs.get('token')
        if not self.is_valid_invitation_link(request, uid, token):
            '''
            If the invitation link is not valid, return JSON that link is not valid
            '''
            response = Response({_('Activation link not valid')}, status=status.HTTP_404_NOT_FOUND)
            response.accepted_renderer = renderers.JSONRenderer()
            response.accepted_media_type = "application/json"
            response.renderer_context = {'request': request}
            return response

        '''
        If the invitation link is valid, proceed with the registration process
        '''
        return super().dispatch(request, *args, **kwargs)

    def perform_create(self, serializer):
        company = Company.objects.filter(pk=self.company).first()
        user = serializer.save(self.request, company=company)
        if allauth_settings.EMAIL_VERIFICATION != \
                allauth_settings.EmailVerificationMethod.MANDATORY:
            if getattr(settings, 'REST_USE_JWT', False):
                self.access_token, self.refresh_token = jwt_encode(user)
            elif not getattr(settings, 'REST_SESSION_LOGIN', False):
                # Session authentication isn't active either, so this has to be
                #  token authentication
                create_token(self.token_model, user, serializer)

        complete_signup(
            self.request._request, user,
            allauth_settings.EMAIL_VERIFICATION,
            None,
        )
        invitation = Invitation.objects.filter(email=user.email).first()
        invitation.used = True
        invitation.save()
        return user

class AdminAccountView(generics.ListAPIView):
    serializer_class = AccountsSerializer
    permission_classes = [IsSuperAdmin]
    def get_queryset(self):
        return Account.objects.filter(is_companyadmin=True)
      
class AdminAccountCreateView(generics.CreateAPIView):
    serializer_class = AccountsSerializer
    permission_classes = [IsSuperAdmin]

    def create(self, request, *args, **kwargs):
        password1 = request.data.get('password1')
        password2 = request.data.get('password2')

        if password1 and password2 and password1 == password2:
            # Validate the passwords and create a new Account instance
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            headers = self.get_success_headers(serializer.data)
            return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)
        else:
            return Response({'password': 'Passwords do not match'}, status=status.HTTP_400_BAD_REQUEST)
    def perform_create(self, serializer):
        password = self.request.data.get('password1')

        if password:
            serializer.save(is_companyadmin=True, is_staff=True, password=make_password(password))
        else:
            raise ValidationError({'password': 'Passwords do not match'})


class IpAddressView(generics.ListAPIView):
    serializer_class = IPAddressFullSerializer
    queryset = IPAddress.objects.all()