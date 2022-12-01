from rest_framework import serializers
from .models import Account, IPAddress


class IPAddressSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = IPAddress
        fields = ['ip_address']

class AccountSerializer(serializers.HyperlinkedModelSerializer):
    ip_address = IPAddressSerializer
    class Meta:
        model = Account
        fields = ['email', 'username', 'ip_address']
    