from rest_framework import serializers, exceptions
from .models import Account, IPAddress, Invitation, Company
from django.contrib.auth import get_user_model, authenticate
from django.core.exceptions import ObjectDoesNotExist
from dj_rest_auth.registration.serializers import RegisterSerializer
from dj_rest_auth.serializers import LoginSerializer, UserDetailsSerializer
from .adapter import activate_ip
from ipware import get_client_ip
from allauth.account.adapter import get_adapter 
from .adapter import send_registration_invite
from rest_framework.response import Response

from rest_framework.exceptions import ValidationError
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

        # print(user.ip_address)
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

class AccountDetailsSerializer(serializers.ModelSerializer):
    ip_address = serializers.StringRelatedField(many=True)
    company = serializers.StringRelatedField()
    class Meta:
        model = Account
        fields = ['email', 'first_name', 'last_name', 'ip_address', 'company']
        read_only_fields = ('pk', 'email', 'ip_address')

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

class AccountsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account
        fields = ['id',
            "email",
            "first_name",
            "last_name",]

        
class IPAddressFullSerializer(serializers.ModelSerializer):
    account = serializers.StringRelatedField()

    class Meta:
        model = IPAddress
        fields = ['id', 'ip_address', 'verified', 'account']