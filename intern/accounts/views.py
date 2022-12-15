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
from .serializers import CompanySerializer, InvitationSerializer
from .permissions import IsCompanyAdmin, IsSuperAdmin
from dj_rest_auth.registration.views import RegisterView
from django.views.generic import TemplateView

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

    ip_address = {"ip_address": uid[1], "verified": True}
    ip_address = IPAddress.objects.create(
        account=Account.objects.get(email=uid[0]), **ip_address)

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
    #permission_classes = [IsAuthenticated]
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
        self.deactivate_company()
        return Response(serializer.data)


class InvitationViewSet(viewsets.ModelViewSet):
    serializer_class = InvitationSerializer
    queryset = Invitation.objects.all()

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
        email = force_str(urlsafe_base64_decode(uid))
        '''Check if a valid invitation exists in the database 
        for the given email address and token
        '''
        invitation = Invitation.objects.filter(email=email).first()
        if invitation is None:
            '''Check if token is valid for given user'''
            if not registration_activation_token.check_token(uid, token):
                return False
        if invitation:
            invitation.accept()
            invitation.save()

    # If a valid invitation is found, return True
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