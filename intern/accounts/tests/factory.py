from faker import Faker as FakerClass
from typing import Any, Sequence
from factory import django, Faker, post_generation

from ..models import Account, IPAddress



class AccountFactory(django.DjangoModelFactory):

    class Meta:
        model = Account
    
    username = Faker('user_name')
    email = Faker('email')
    first_name = Faker('first_name')
    last_name = Faker('last_name')


    @post_generation
    def password(self, create: bool, extracted: Sequence[Any], **kwargs):
        password = (
            extracted
            if extracted
            else FakerClass().password(
                length=30,
                special_chars=True,
                digits=True,
                upper_case=True,
                lower_case=True,
            )
        )
        self.set_password(password)

class IPAddressFactory(django.DjangoModelFactory):
    class Meta:
        model = IPAddress

    ip_address = Faker('ipv4')
    verified = True
    account = AccountFactory.build()