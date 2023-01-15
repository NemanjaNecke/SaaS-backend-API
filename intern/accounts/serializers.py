from rest_framework import serializers, exceptions
from .models import Account, IPAddress, Invitation, Company
from django.contrib.auth import get_user_model, authenticate
from django.core.exceptions import ObjectDoesNotExist
from dj_rest_auth.registration.serializers import RegisterSerializer
from dj_rest_auth.serializers import LoginSerializer, PasswordResetSerializer, PasswordResetConfirmSerializer
from .adapter import activate_ip
from ipware import get_client_ip
from allauth.account.adapter import get_adapter 
from .adapter import send_registration_invite
from rest_framework.response import Response
from rest_framework.exceptions import ValidationError
from django.conf import settings
from dj_rest_auth.forms import AllAuthPasswordResetForm
from django.utils.encoding import force_str
from allauth.account.forms import default_token_generator
from django.utils.http import urlsafe_base64_decode as uid_decoder
from django.contrib.auth.forms import PasswordResetForm
from .models import Task
from rest_framework import status



class IPAddressSerializer(serializers.Serializer):
    class Meta:
        model = IPAddress
        fields = ['ip_address']

class AccountRegisterSerializer(RegisterSerializer):
    first_name = serializers.CharField(max_length=50)
    last_name = serializers.CharField(max_length=50)
    username = None
    class Meta:
        model = Account
        fields = [
            "email",
            "first_name",
            "last_name",
            "password",
        ]

    def get_cleaned_data(self):
        return {
            "email": self.validated_data.get("email", ""),
            "first_name": self.validated_data.get("first_name", ""),
            "last_name": self.validated_data.get("last_name", ""),
            "password1": self.validated_data.get("password1", ""),
            "password2": self.validated_data.get("password2", ""),
        }


    def save(self, request, company):
        adapter = get_adapter()
        user = adapter.new_user(request)
        self.cleaned_data = self.get_cleaned_data()
        user.first_name = self.cleaned_data.get("first_name")
        user.last_name = self.cleaned_data.get("last_name")
        user.company = company
        adapter.save_user(request, user, self)
        user.save()
        '''Save the IP address of the user on sign up to use it as the default IP address'''
        ip_address = {"ip_address": get_client_ip(request)[0]}
        IPAddress.objects.create(account=user, **ip_address)

        return user


class AccountLoginSerializer(LoginSerializer):
    username = None

    def authenticate(self, **options):
        return authenticate(self.context["request"], **options)

    def validate(self, attrs):
        email = attrs.get("email")
        ip_address = get_client_ip(self.context["request"])[0]
        password = attrs.get("password")
        if email and password:
            '''Check if IP address belongs to account with given email address'''
            try:
                if Account.objects.get(email=email).ip_address.filter(ip_address=ip_address).exists():
                    user = authenticate(
                    email=email,
                    password=password,
                    )
                else:
                    activate_ip(self.context['request'], email, ip_address)
                    msg = "IP address doesn't match. An email has been sent to verify this IP address."

                    raise serializers.ValidationError(msg, code="authorization")
                if not user:
                    msg = "Invalid credentials."
                    raise serializers.ValidationError(msg, code="authorization")      
            except ObjectDoesNotExist:
                msg = "Invalid credentials."
                raise serializers.ValidationError(msg, code="authorization")
        else:
            msg = "No email provided."
            raise exceptions.ValidationError(msg)
        self.validate_email_verification_status(user)

        attrs["user"] = user

        return attrs

class CompanySerializer(serializers.ModelSerializer):
    class Meta:
        model = Company
        fields = ['id','name', 'admin', 'active_until', 'is_active', 'accounts']
        read_only_fields = ['id', 'accounts']
        lookup_field = 'name'
        extra_kwargs = {
            'url': {'lookup_field': 'name'}
        }

class CompanyListSerializer(serializers.ModelSerializer):
    admin = serializers.StringRelatedField()
    accounts = serializers.StringRelatedField(many=True)
    class Meta:
        model = Company
        fields = ['id','name', 'admin', 'active_until', 'is_active', 'accounts']

class AccountDetailsSerializer(serializers.ModelSerializer):
    ip_address = serializers.StringRelatedField(many=True)
    company = serializers.SlugRelatedField(
        slug_field='name',
        queryset=Company.objects.all()
    )
    class Meta:
        model = Account
        fields = ['id','email', 'first_name', 'last_name', 'ip_address', 'company']
        read_only_fields = ('pk', 'email', 'ip_address')

class AccountListSerializer(serializers.ModelSerializer):
    company = serializers.SlugRelatedField(
        slug_field='name',
        queryset=Company.objects.all()
    )
    class Meta:
        model = Account
        fields = ['id','email', 'first_name', 'last_name', 'company']
        read_only_fields = ('pk', 'email', 'ip_address')        

class PasswordResetSerializer(PasswordResetSerializer):
    @property
    def password_reset_form_class(self):
        use_custom_email_template = bool(self.get_email_options().get("html_email_template_name", ''))
        if 'allauth' in settings.INSTALLED_APPS and not use_custom_email_template:
            return AllAuthPasswordResetForm
        else:
            return PasswordResetForm
    def get_email_options(self):
        return {
            'html_email_template_name': 'account/email/password_reset_email.html',
        }

class CustomPasswordResetConfirmSerializer(PasswordResetConfirmSerializer):
    def validate(self, attrs):
        # Decode the uidb64 (allauth use base36) to uid to get User object
        try:
            uid = force_str(uid_decoder(attrs['uid']))
            self.user = Account.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, ObjectDoesNotExist):
            raise ValidationError({'uid': ['Invalid value']})

        if not default_token_generator.check_token(self.user, attrs['token']):
            raise ValidationError({'token': ['Invalid value']})

        self.custom_validation(attrs)
        # Construct SetPasswordForm instance
        self.set_password_form = self.set_password_form_class(
            user=self.user, data=attrs,
        )
        if not self.set_password_form.is_valid():
            raise serializers.ValidationError(self.set_password_form.errors)

        return attrs

class InvitationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Invitation
        fields = ['id','email', 'invited_by', 'accepted', 'used']
        read_only_fields = ('id','accepted', 'used')

    def get_cleaned_data(self):
        return {
            "email": self.validated_data.get("email", ""),
            "invited_by": self.validated_data.get("invited_by","")
        }

    def save(self, instance, request):        
        self.cleaned_data = self.get_cleaned_data()
        instance.email = self.cleaned_data.get("email")
        instance.invited_by = self.cleaned_data.get("invited_by")

        try:
            company = Company.objects.get(admin=instance.invited_by.pk)
        except ObjectDoesNotExist:
            raise ValidationError("Company not found")
        instance.save()
        send_registration_invite(request, instance.email, company, instance.invited_by)
        return instance

class InviteListSerializer(serializers.ModelSerializer):
    invited_by = serializers.StringRelatedField()
    class Meta:
        model = Invitation
        fields = ['email', 'invited_by', 'accepted', 'used', 'id']

class AccountsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account
        fields = ['id', "email","first_name","last_name",]

        
class IPAddressFullSerializer(serializers.ModelSerializer):
    account = serializers.StringRelatedField()

    class Meta:
        model = IPAddress
        fields = ['id', 'ip_address', 'verified', 'account']

class TaskSerializer(serializers.ModelSerializer):
    company = serializers.StringRelatedField(read_only=True, required=False)
    created_by = serializers.StringRelatedField(read_only=True, required=False)
    
    class Meta:
        model = Task
        fields = '__all__'

    def create(self, validated_data):
        request = self.context['request']
        account = request.user

        validated_data.pop('company', None)
        validated_data.pop('created_by', None)
        responsible_user = validated_data["responsible_user"]
        try:
            company = Company.objects.get(accounts=account)
        except Company.DoesNotExist:
            try:
                company = Company.objects.get(admin=account)
            except Company.DoesNotExist:
                company = Company.objects.get(accounts=responsible_user)
        validated_data['company'] = company
        validated_data['created_by'] = account
        # Check if the super_admin is making a request
        if account.is_superadmin:

            task = Task.objects.create(**validated_data)
            return task
        # Check if user is from the same company
        elif validated_data["responsible_user"] in company.accounts.all():

        # Create and return the task
            task = Task.objects.create(**validated_data)
            return task
        else:
            raise ValidationError("The account that this task is created for doesn't belong to your company")

class ResponseTaskSeriliazer(serializers.ModelSerializer):
    company = serializers.StringRelatedField(read_only=True, required=False)
    created_by = serializers.StringRelatedField(read_only=True, required=False)
    responsible_user = serializers.StringRelatedField(read_only=True)
    class Meta:
        model = Task
        fields = '__all__'

class UserTaskSerializer(serializers.ModelSerializer):
    company = serializers.StringRelatedField(read_only=True, required=False)
    created_by = serializers.StringRelatedField(read_only=True, required=False)
    responsible_user = serializers.StringRelatedField(read_only=True)
    class Meta:
        model = Task
        exclude = ['currency', 'value']

