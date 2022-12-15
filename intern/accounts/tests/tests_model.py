from django.test import TestCase
from django.contrib.auth import get_user_model
from ..models import IPAddress, Company, Account, Invitation
from .factory import AccountFactory
from datetime import datetime, timedelta
from django.utils import timezone


class ModelTests(TestCase):

    def test_create_account_with_email(self):
        email = 'test@gmail.com'
        password = 'testpass123'
        account = get_user_model().objects.create_account(
            email=email,
            password=password
        )

        self.assertEqual(account.email, email)
        self.assertTrue(account.check_password(password))

    def test_account_email_normalizer(self):
        email = 'test@GMAIL.COM'
        account = get_user_model().objects.create_account(email, 'test123')

        self.assertEqual(account.email, email.lower())

    def test_account_email_invalid(self):
        with self.assertRaises(ValueError):
            get_user_model().objects.create_account(None, 'test123')

    def test_create_super_user(self):
        account = get_user_model().objects.create_superuser(
            'test@gmail.com',
            'Test123'
        )

        self.assertTrue(account.is_superuser)
        self.assertTrue(account.is_staff)

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
    
    def test_admin_user(self):
        account = get_user_model().objects.create_admin(
                'test@gmail.com',
                'Test123'
            )
        self.assertTrue(account.is_admin)
        self.assertTrue(account.is_staff)
        self.assertTrue(account.is_companyadmin)

    def test_superadmin(self):
        account = get_user_model().objects.create_superadmin(
                'test@gmail.com',
                'Test123'
            )
        self.assertTrue(account.is_admin)
        self.assertTrue(account.is_staff)
        self.assertTrue(account.is_companyadmin)
        self.assertTrue(account.is_superadmin)

class CompanyModelTestCase(TestCase):

    def setUp(self):
        self.account1, self.account2, self.account3, self.account4, self.account5, self.account6 = AccountFactory.create_batch(6)
        self.admin = get_user_model().objects.create_admin(
                'test2@gmail.com',
                'Test123'
            )
        self.admin2 = get_user_model().objects.create_admin(
                'test3@gmail.com',
                'Test123'
            )
        self.company = Company.objects.create(name='company1', admin=self.admin)
    def test_accounts_with_company(self):
        
        #Assign company to accounts
        self.account1.company = self.company
        self.account1.save()
        self.account2.company = self.company
        self.account2.save()
        self.account3.company = self.company
        self.account3.save()
        self.account4.company = self.company
        self.account4.save()
        self.account5.company = self.company
        self.account5.save()
        self.account6.company = self.company
        self.account6.save()
        

        #Test that accounts belong to a company accounts relation
        accounts = self.company.accounts.all()
        self.assertEqual(self.account1.company, self.company)
        self.assertEqual(self.account2, accounts.get(email=self.account2.email))
        self.assertTrue(accounts.filter(first_name=self.account3.first_name).exists())


    def test_is_active_property(self):
        # By default, a company should be active
        self.assertTrue(self.company.is_active)

        # Set the company's active_until date to 90 days in the past
        self.company.active_until = timezone.make_aware(
            datetime.now() - timedelta(days=90)
            )
        self.company.save()

        # The company should no longer be active
        self.assertFalse(self.company.is_active)

    def test_deactivate_method(self):
        # The user should not be able to deactivate the company if they are
        # not a superadmin
        self.assertRaises(
            PermissionError,
            self.company.deactivate,
            self.admin2
        )

        # Make the user a superadmin
        self.admin2.is_superadmin = True
        self.admin2.save()

        # The user should now be able to deactivate the company
        self.company.deactivate(self.admin2)

        # The company should no longer be active
        self.assertFalse(self.company.is_active)

class InvitationModelTestCase(TestCase):

    def setUp(self):
        self.account1, self.account2, self.account3, self.account4, self.account5, self.account6 = AccountFactory.create_batch(6)
        self.admin = get_user_model().objects.create_admin(
                'test2@gmail.com',
                'Test123'
            )
        self.admin2 = get_user_model().objects.create_admin(
                'test3@gmail.com',
                'Test123'
            )
    def test_invitation_model(self):
    # Create an invitation
        invitation = Invitation.objects.create(
        email="test@example.com",
        invited_by=self.admin
        )
        self.assertFalse(invitation.accepted)

    # Accept the invitation
        invitation.accept()
        self.assertTrue(invitation.accepted)

    # Check that the invitation was saved
        invitation.refresh_from_db()
        self.assertTrue(invitation.accepted)