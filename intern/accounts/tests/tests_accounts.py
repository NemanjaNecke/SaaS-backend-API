from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse

from rest_framework.test import APIClient
from rest_framework import status
from ..urls import urlpatterns

CREATE_ACCOUNT_URL = reverse(r'auth/register/')
# ACCOUNT_CONFIRM_EMAIL = reverse(r'auth/account_confirm_email')

def create_account(**params):
    return get_user_model().objects.create_account(**params)


class PublicAccountAPITest(TestCase):

    def setUP(self):
        self.client = APIClient()

    def test_create_valid_account(self):

        payload = {
            "username": 'Test',
            "email": 'test@gmail.com',
            "password1": 'ingest1234',
            "password2": 'ingest1234',
            "first_name": 'Test1',
            "last_name": 'Test2'
        }
        """Test doesn't pass the confirm email part 
        update needed
        """
        print(reverse('auth/register/'))
        res = self.client.post(urlpatterns[4], payload)
        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        user = get_user_model().objects.get(**res.data)
        self.assertTrue(user.check_password(payload['password1']))
        self.assertNotIn('password', res.data)
