from rest_framework import serializers
from .models import Account, IPAddress
from rest_framework import serializers, exceptions
from .models import Account, IPAddress
from django.contrib.auth import get_user_model, authenticate
from django.core.exceptions import ObjectDoesNotExist
from dj_rest_auth.registration.serializers import RegisterSerializer
from dj_rest_auth.serializers import LoginSerializer, UserDetailsSerializer
from allauth.account.adapter import get_adapter
from ipware import get_client_ip
from .adapter import activate_ip


class IPAddressSerializer(serializers.Serializer):
    class Meta:
        fields = ['pk', 'ip_address']

class AccountRegisterSerializer(RegisterSerializer):
    username = serializers.CharField(max_length=50)
    first_name = serializers.CharField(max_length=50)
    last_name = serializers.CharField(max_length=50)

    class Meta:
        model = Account
        fields = [
            "email",
            "username",
            "first_name",
            "last_name",
            "password",
        ]

    def get_cleaned_data(self):
        return {
            "username": self.validated_data.get("username", ""),
            "email": self.validated_data.get("email", ""),
            "first_name": self.validated_data.get("first_name", ""),
            "last_name": self.validated_data.get("last_name", ""),
            "password1": self.validated_data.get("password1", ""),
            "password2": self.validated_data.get("password2", ""),
        }

    def save(self, request):
        adapter = get_adapter()
        user = adapter.new_user(request)
        self.cleaned_data = self.get_cleaned_data()
        user.username = self.cleaned_data.get("username")
        user.first_name = self.cleaned_data.get("first_name")
        user.last_name = self.cleaned_data.get("last_name")
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

class AccountDetailsSerializer(UserDetailsSerializer):
    ip_address = serializers.StringRelatedField(many=True)
    class Meta:
        fields = ['email', 'username', 'first_name', 'last_name', 'ip_address']
        read_only_fields = ('pk', 'email','ip_address')
        model = Account