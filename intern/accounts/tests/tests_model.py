from django.test import TestCase
from django.contrib.auth import get_user_model
from ..models import IPAddress


class ModelTests(TestCase):

    def test_create_account_with_email(self):
        email = 'test@gmail.com'
        password = 'testpass123'
        user = get_user_model().objects.create_account(
            email=email,
            password=password
        )

        self.assertEqual(user.email, email)
        self.assertTrue(user.check_password(password))

    def test_account_email_normalizer(self):
        email = 'test@GMAIL.COM'
        user = get_user_model().objects.create_account(email, 'test123')

        self.assertEqual(user.email, email.lower())

    def test_account_email_invalid(self):
        with self.assertRaises(ValueError):
            get_user_model().objects.create_account(None, 'test123')

    def test_create_super_user(self):
        user = get_user_model().objects.create_superuser(
            'test@gmail.com',
            'Test123'
        )

        self.assertTrue(user.is_superuser)
        self.assertTrue(user.is_staff)

    def test_ip_address(self):
        account = get_user_model().objects.create_account(
                'test@gmail.com',
                'Test123'
            )
        ip = '127.0.0.1'
        ip_address = IPAddress.objects.create(ip_address=ip,account=account)

        self.assertEqual(ip_address.ip_address, ip)
        self.assertEqual(ip_address.account, account)
        self.assertTrue(ip_address.verified)
