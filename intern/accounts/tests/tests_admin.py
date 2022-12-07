from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.urls import reverse


class AdminSiteTests(TestCase):

    def setUp(self):
        self.client = Client()
        self.admin_account = get_user_model().objects.create_superuser(
            email='admin@gmail.com',
            password='password123'
        )

        self.client.force_login(self.admin_account)
        self.user = get_user_model().objects.create_account(
            email='test@gmail.com',
            password='test123',
            username='testusername',
            first_name='firstname',
            last_name='lastname',
        )

    def test_accounts_listed(self):
        url = reverse('admin:accounts_account_changelist')
        res = self.client.get(url)

        self.assertContains(res, self.user.username)
        self.assertContains(res, self.user.email)
        self.assertContains(res, self.user.first_name)
        self.assertContains(res, self.user.last_name)

    def test_account_change_page(self):
        url = reverse('admin:accounts_account_change', args=[self.user.id])
        res = self.client.get(url)

        self.assertEqual(res.status_code, 200)

    def test_account_add(self):
        url = reverse('admin:accounts_account_add')
        res = self.client.get(url)

        self.assertEqual(res.status_code, 200)