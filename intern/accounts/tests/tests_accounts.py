from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse
from .factory import AccountFactory, IPAddressFactory
from rest_framework.test import APIClient, APITestCase
from rest_framework import status
import json
from factory import Faker
from ..models import Account

class AccountSignUpTest(APITestCase):

    @classmethod
    def setUpClass(self):
        super().setUpClass()

        self.account_object = AccountFactory.build()
        self.account_saved = AccountFactory.create()
        self.client = APIClient()
        self.signup_url = reverse('rest_register')
        # self.faker_obj = Faker()

    def test_if_data_is_correct_then_signup(self):
        # Prepare data
        payload = {
            'username': self.account_object.username,
            'password1': 'test_Pass',
            'password2': 'test_Pass',
            'email': self.account_object.email,
            'first_name': self.account_object.first_name,
            'last_name': self.account_object.last_name
        }

        response = self.client.post(self.signup_url, json.dumps(
            payload), content_type='application/json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Account.objects.count(), 2)

        new_account = Account.objects.get(
            username=self.account_object.username)

        self.assertEqual(
            new_account.first_name,
            self.account_object.first_name,
        )
        self.assertEqual(
            new_account.email,
            self.account_object.email,
        )

    def test_if_username_already_exists_dont_signup(self):

        payload={
            'username': self.account_saved.username,
            'password1': 'test_Pass',
            'password2': 'test_Pass',
            'phone_number': self.account_saved.email,
            'category': self.account_saved.first_name,
            'last_name': self.account_saved.last_name
        }


        response = self.client.post(self.signup_url, json.dumps(
            payload), content_type='application/json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            str(response.data['username'][0]),
            'Account with this username already exists.',
        )

        username_query=Account.objects.filter(
            username = self.account_saved.username)
        self.assertEqual(username_query.count(), 1)
