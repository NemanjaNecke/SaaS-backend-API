from django.forms import ValidationError
from django.shortcuts import redirect, get_object_or_404
from rest_framework import viewsets, generics, mixins, renderers, filters
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.decorators import action
from allauth.account.models import EmailAddress
from dj_rest_auth.registration.serializers import ResendEmailVerificationSerializer
from rest_framework import status
from django.core.exceptions import ObjectDoesNotExist
from django.utils.translation import gettext_lazy as _
from accounts.models import IPAddress, Account, Company, Invitation, Task
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from rest_framework.pagination import PageNumberPagination
from .filters import TaskFilter
from .adapter import account_activation_token, registration_activation_token
from rest_framework.decorators import api_view, renderer_classes
from rest_framework.renderers import JSONRenderer, TemplateHTMLRenderer
from accounts.serializers import AccountListSerializer, ResponseTaskSeriliazer, AccountDetailsSerializer, InviteListSerializer, UserTaskSerializer, CompanyListSerializer,AccountsSerializer, CompanySerializer, IPAddressFullSerializer, InvitationSerializer, PasswordResetSerializer, TaskSerializer
from .permissions import IsCompanyAdmin, IsSuperAdmin, IsSuperAdminOrCompanyAdmin
from dj_rest_auth.registration.views import RegisterView
from django.views.generic import TemplateView
from allauth.account.utils import complete_signup
from django.conf import settings
from allauth.account import app_settings as allauth_settings
from dj_rest_auth.app_settings import create_token
from dj_rest_auth.utils import jwt_encode
from django.contrib.auth.hashers import make_password
from django.db import IntegrityError
from dj_rest_auth.views import PasswordResetView
from django.utils import timezone
from datetime import datetime, timedelta
from django.db.models import Q
from django_filters.rest_framework import DjangoFilterBackend
from django.db.models import Count, Sum


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


class CustomPasswordResetView(PasswordResetView):
    serializer_class = PasswordResetSerializer


@api_view(('GET',))
@renderer_classes((JSONRenderer,))
def activate(request, uidb64, token):
    uid = force_str(urlsafe_base64_decode(uidb64)).split('-')
    account = Account.objects.get(email=uid[0])
    ip_address = {"ip_address": uid[1], "verified": True}
    try:
        ip_address = IPAddress.objects.create(
            account=account, **ip_address)
    except IntegrityError:
        return Response({_('Activation link already used')}, status=status.HTTP_404_NOT_FOUND)

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
    

    @action(detail=False, methods=['create'])
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        company = serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def list(self, request):
  # Get the filtered queryset using the filter set
        queryset = self.filter_queryset(self.get_queryset())

    # If the user is a superuser or a company admin, return all companies
        if request.user.is_superuser:
            serializer = CompanyListSerializer(queryset, many=True)
            return Response(serializer.data)

    # Otherwise, return only the company that the user is an admin of
        else:
            company = queryset.get(admin=request.user)
            serializer = CompanyListSerializer(company)
            return Response(serializer.data)

    @action(detail=True, methods=['put'], permission_classes=[IsSuperAdmin])
    # dodaj permissions za super admin i handler ako nije
    def deactivate_company(self, request, pk=None, name=None):

        account = request.user
        company = get_object_or_404(self.queryset)
        serializer = CompanySerializer(company)

        company.deactivate(account)
        company.save()
        return Response(serializer.data)

    @action(detail=True, methods=['put'], permission_classes=[IsSuperAdmin])
    def activate_company(self, request, pk=None, name=None):

        account = request.user
        company = get_object_or_404(self.queryset)
        serializer = CompanySerializer(company)

        company.activate(account)
        company.save()
        return Response(serializer.data)


class InvitationViewSet(viewsets.ModelViewSet):
    serializer_class = InvitationSerializer
    queryset = Invitation.objects.all()
    permission_classes = [IsSuperAdminOrCompanyAdmin]

    def get_queryset(self):
        request = self.request
        account = request.user

        try:
            company_admin = Company.objects.get(admin=account)

        except Company.DoesNotExist:
            company_admin = None

        queryset = self.queryset

    # Check if the user is a superadmin or a company admin
        if account.is_superuser:
            queryset
        # Return the full queryset, filtered by the company if the user is a company admin
        elif company_admin:
            queryset = queryset.filter(Q(invited_by=account))
        
        return queryset

    def create(self, request):
        serializer = self.get_serializer(
            data=request.data, context={'request': request})
        try:
            serializer.is_valid(raise_exception=True)
            invitation = Invitation(**serializer.validated_data)
            invitation = serializer.save(invitation, request)
            response_data = serializer.data
        except ValidationError as e:
            return Response({'error': e.detail}, status=status.HTTP_400_BAD_REQUEST)

        response_data.update({'detail': _('Invite sent successfully')})
        return Response(response_data, status=status.HTTP_201_CREATED)

    def list(self, request):
        serializer = InviteListSerializer(self.get_queryset(), many=True)
        return Response(serializer.data)

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
        if invitation is None or invitation.used == True or not registration_activation_token.check_token(email, token):

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
            response = Response({_('Activation link not valid')},
                                status=status.HTTP_404_NOT_FOUND)
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


class UserAccountView(generics.RetrieveAPIView):
    serializer_class = AccountDetailsSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user
        
class UserAccounts(generics.ListAPIView):
    serializer_class = AccountListSerializer
    queryset = Account.objects.all()
    def get_queryset(self):
        user = self.request.user
        # If the user is a superuser, return the full queryset
        if user.is_superadmin:
            return Account.objects.all()
        # Otherwise, return only the objects that belong to user's or admin's company
        return Account.objects.filter(company=user.company)

class AdminAccountUpdateView(generics.RetrieveUpdateAPIView):
    serializer_class = AccountDetailsSerializer
    permission_classes = [IsSuperAdmin]
    queryset = Account.objects.all()

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
            serializer.save(is_companyadmin=True, is_staff=True,
                            password=make_password(password))
        else:
            raise ValidationError({'password': 'Passwords do not match'})


class IpAddressView(generics.ListAPIView):
    serializer_class = IPAddressFullSerializer
    #permission_classes = [IsAuthenticated]
    ordering_fields = ('account', 'ip_address')
    def get_queryset(self):
        # Get the logged in user
        user = self.request.user
        # If the user is a superuser, return the full queryset
        if user.is_superadmin:
            return IPAddress.objects.all()
        # Otherwise, return only the objects that belong to the user
        return IPAddress.objects.filter(account=user)


class TaskView(viewsets.ModelViewSet):
    pagination_class = PageNumberPagination
    pagination_class.page_size = 10
    serializer_class = TaskSerializer
    queryset = Task.objects.all()
    ordering_fields = ('due_date', 'priority', 'created_by')
    filterset_class = TaskFilter
    search_fields = ['company', 'responsible_user__email', 'created_by__email']

    def create(self, request):
        if request.method == 'POST':

            data = self.request.data
            if 'due_date' not in data or data['due_date'] is None:
                due_date = timezone.make_aware(
                    datetime.now() + timedelta(days=1))
                due_date_str = due_date.strftime("%Y-%m-%d %H:%M:%S")
                data['due_date'] = due_date_str
            serializer = TaskSerializer(
                data=data, context={'request': request})
            if serializer.is_valid():
                serializer.save()
                response = {
                    'detail': 'Task created Successfully!',
                    'data': serializer.data
                }

                return Response(data=response, status=status.HTTP_201_CREATED)
            else:
                errors = {}
                for field, error in serializer.errors.items():
                    errors[field] = error[0]
                return Response({'detail': _('Request not valid'), 'errors': errors}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'detail': _('Method not allowed')}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def list(self, request):
 
        # Get the filtered queryset using the filter set
        queryset = self.filter_queryset(self.get_queryset())
        # Get analytics
        analytics = self.get_analytics(request, queryset)
       # Pagination
        page = self.paginate_queryset(queryset)
        # if page is not None:
        #     serializer = TaskSerializer(page, many=True)
        #     return 
        # Get serializer
        serializer = ResponseTaskSeriliazer(queryset, many=True)
        # Check if the user is a superadmin or a companyadmin
        if request.user.is_superuser or request.user.is_companyadmin:
            # If the user is a superadmin or a companyadmin, show the analytics

            # Return the analytics data in the response
            return self.get_paginated_response({
           # 'analytics':analytics,
            'data': serializer.data,
        })

        else:
            # If the user is not a superadmin or a companyadmin, show only the response data
            serializer = UserTaskSerializer(queryset, many=True)
            return self.get_paginated_response({'data':serializer.data})

    def get_analytics(self, request, queryset):
        # Initialize the analytics data
        analytics = {
            'total_tasks': 0,
            'tasks_value_per_priority': [],
            'task_per_status':[],
            'total_value': 0, 
            'tasks_per_category': [],
            'task_value_per_category': [],
            'task_value_per_status': [],
            'tasks_per_status_and_category': []
        }

    # Get the total number of tasks
        analytics['total_tasks'] = queryset.count()
    # Get the task per status number
        task_per_status = queryset.values('status').annotate(
            count=Count('id')).order_by('status')
        for task in task_per_status:
            analytics['task_per_status'].append({
                'status': task['status'],
                'count': task['count']
            })
    # Get the total value of all tasks
        analytics['total_value'] = queryset.aggregate(Sum('value'))[
            'value__sum']
    # Get the value of tasks per priority
        tasks_value_per_priority = queryset.values('priority').annotate(
            sum=Sum('value')).order_by('priority')
        for task in tasks_value_per_priority:
            analytics['tasks_value_per_priority'].append({
                'priority': task['priority'],
                'value': task['sum']
            })
    # Get the value of each task per category
        task_value_per_category = queryset.values('category').annotate(
            sum=Sum('value')).order_by('category')
        for task in task_value_per_category:
            analytics['task_value_per_category'].append({
                'category': task['category'],
                'value': task['sum']
            })
        # Calculate the value of each task per status
        task_value_per_status = queryset.values('status').annotate(
            sum=Sum('value')).order_by('status')
        for task in task_value_per_status:
            analytics['task_value_per_status'].append({
            'status': task['status'],
            'value': task['sum']
            })
    # Get the number of tasks per category
        tasks_per_category = queryset.values('category').annotate(
            count=Count('id')).order_by('category')
        for task in tasks_per_category:
            analytics['tasks_per_category'].append({
                'category': task['category'],
                'count': task['count']
            })
    # Get the value of task per category and status
        tasks_per_status_and_category = queryset.values('status', 'category').annotate(
        value=Sum('value')).order_by('status', 'category')

        analytics['tasks_per_status_and_category'] = []
        for task in tasks_per_status_and_category:
            analytics['tasks_per_status_and_category'].append({
            'status': task['status'],
            'category': task['category'],
            'value': task['value']
        })

        return analytics

    def get_queryset(self):
        request = self.request
        account = request.user

        try:
            company_admin = Company.objects.get(admin=account)
        except Company.DoesNotExist:
            company_admin = None

        queryset = self.queryset

    # Check if the user is a superadmin or a company admin
        if account.is_superuser:
            queryset
        # Return the full queryset, filtered by the company if the user is a company admin
        elif company_admin:
            queryset = queryset.filter(company=company_admin)

        else:
            # Return only the tasks that are made by or assigned to the user
            queryset = queryset.filter(
                Q(created_by=account) | Q(responsible_user=account))

        return queryset

class TaskAnalyticsView(TaskView):
    def list(self, request):
        queryset = self.filter_queryset(self.get_queryset())
        analytics = self.get_analytics(request, queryset)
        return Response({'analytics': analytics})