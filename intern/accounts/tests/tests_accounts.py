from django.template import TemplateDoesNotExist
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse
from .factory import AccountFactory, IPAddressFactory
from rest_framework.test import APIClient, APITestCase
from rest_framework import status
import json
from ..models import Account, IPAddress, Invitation
from allauth.account.models import EmailAddress
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from ..adapter import registration_activation_token


class UserSignUpTestCase(APITestCase):

    @classmethod
    def setUpClass(self):
        super().setUpClass()
        self.account_object = AccountFactory.build()
        self.account_saved = AccountFactory.create()
        # Admin needs to be created to create an invite
        self.admin = get_user_model().objects.create_admin(
                'test3@gmail.com',
                'Test123'
            )
        self.client = APIClient()
        # Invite needs to be created so the link generation would work
        invitation = Invitation.objects.create(email=self.account_object.email, invited_by=self.admin)
        self.uidb64 = urlsafe_base64_encode(force_bytes(self.account_object.email))
        self.token = registration_activation_token.make_token(self.account_object.email)
        self.signup_url = reverse('register', args= (self.uidb64, self.token))

    def test_if_data_is_correct_then_signup(self):
        # Prepare data
        payload = {
            'password1': self.account_object.password,
            'password2': self.account_object.password,
            'email': self.account_object.email,
            'first_name': self.account_object.first_name,
            'last_name': self.account_object.last_name
        }

        response = self.client.post(self.signup_url, 
            json.dumps(payload), 
            content_type='application/json'
        )
        print(response.data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Account.objects.count(), 3)

        new_account = Account.objects.get(
            email=self.account_object.email)

        self.assertEqual(
            new_account.first_name,
            self.account_object.first_name,
        )
        self.assertEqual(
            new_account.email,
            self.account_object.email,
        )

    def test_if_email_already_exists_dont_signup(self):

        payload = {
            'password1': self.account_saved.password,
            'password2': self.account_saved.password,
            'email': self.account_saved.email,
            'first_name': self.account_saved.first_name,
            'last_name': self.account_saved.last_name
        }

        response = self.client.post(self.signup_url, json.dumps(
            payload), content_type='application/json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
   
        self.assertEqual(
            str(response.data['email'][0]),
            'A user is already registered with this e-mail address.',
        )

        email_query = Account.objects.filter(
            email=self.account_saved.email)
        self.assertEqual(email_query.count(), 1)

class LoginTest(APITestCase):

    def setUp(self):
        self.client = APIClient()
        self.login_url = reverse('rest_login')
        ##self.verify_email_url = reverse('account_confirm_email')

    def test_login_credentials(self):

        payload = {
            'email': 'admin@gmail.com',
            'password': 'newthingcoming',

        }
        account = get_user_model().objects.create_account(
            email='admin@gmail.com',
            password='newthingcoming'
        )

        ip_address = IPAddressFactory.create(account=account)

        EmailAddress.objects.create(
            user=account,
            email=account.email,
            primary=True,
            verified=True,
        )

        response = self.client.post(
            self.login_url, 
            json.dumps(payload), 
            REMOTE_ADDR=ip_address.ip_address, 
            content_type='application/json'
            )

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_login_credentials_email_not_verified(self):

        payload = {
            'email': 'admin@gmail.com',
            'password': 'newthingcoming',

        }
        account = get_user_model().objects.create_account(
            email='admin@gmail.com',
            password='newthingcoming'
        )
        ip_address = IPAddressFactory.create(account=account)

        response = self.client.post(
            self.login_url, 
            json.dumps(payload), 
            REMOTE_ADDR=ip_address.ip_address, 
            content_type='application/json'
            )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            str(response.data['non_field_errors'][0]),
            'E-mail is not verified.',
        )
    
    def test_login_credentials_ip_not_verified(self):

        payload = {
            'email': 'admin@gmail.com',
            'password': 'newthingcoming',

        }
        get_user_model().objects.create_account(
            **payload
        )
        ip_address = '217.0.0.1'
  
        response = self.client.post(
            self.login_url, 
            json.dumps(payload), 
            REMOTE_ADDR=ip_address, 
            content_type='application/json'
            )
     

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            str(response.data['non_field_errors'][0]),
            "IP address doesn't match. An email has been sent to verify this IP address.",
        )