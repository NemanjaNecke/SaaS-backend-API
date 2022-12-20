from django.utils import timezone
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from utils.model_abstracts import Model
from django.utils.translation import gettext_lazy as _
from datetime import datetime, timedelta


class AccountManager(BaseUserManager):

    def create_account(self, email, password, **extrafields):
        if not email:
            raise ValueError('Users must have an email address')
        account = self.model(email=self.normalize_email(
            email), password=password, **extrafields)
        account.set_password(password)
        account.save(using=self.db)

        return account

    def create_admin(self, email, password, **extrafields):
        account = self.create_account(
            email=self.normalize_email(email), password=password)
        account.is_staff = True
        account.is_admin = True
        account.is_companyadmin = True

        return account

    def create_superadmin(self, email, password):
        account = self.create_account(
            email=self.normalize_email(email), password=password)
        account.is_staff = True
        account.is_admin = True
        account.is_companyadmin = True
        account.is_superadmin = True

        return account

    def create_superuser(self, email, password):
        account = self.create_account(
            email=self.normalize_email(email), password=password)
        account.is_staff = True
        account.is_admin = True
        account.is_superamdin = True
        account.is_superuser = True
        account.save(using=self.db)

        return account


class Account(AbstractBaseUser, Model, PermissionsMixin):
    email = models.EmailField(max_length=255, unique=True)
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_companyadmin = models.BooleanField(default=False)
    is_superadmin = models.BooleanField(default=False)
    company = models.ForeignKey(
        "Company", on_delete=models.CASCADE, related_name="accounts",
        null=True, blank=True)

    objects = AccountManager()

    USERNAME_FIELD = 'email'
    EMAIL_FIELD = 'email'

    def __str__(self):
        return self.email


class IPAddress(Model):
    ip_address = models.GenericIPAddressField(
        protocol='both', unpack_ipv4=True)
    account = models.ForeignKey(
        Account, on_delete=models.CASCADE, related_name='ip_address')
    verified = models.BooleanField(default=True)

    class Meta:
        verbose_name_plural = 'IPAddresses'
        constraints = [
            models.UniqueConstraint(
                fields=('ip_address', 'account'), name='ip-account')
        ]

    def __str__(self) -> str:
        return self.ip_address


class Company(Model):
    name = models.CharField(max_length=255)

    admin = models.OneToOneField(
        Account, on_delete=models.CASCADE, related_name="company_admin")
    active_until = models.DateTimeField(
        default=timezone.make_aware(datetime.now() + timedelta(days=90)))

    @property
    def is_active(self):
        return self.active_until > timezone.make_aware(datetime.now())

    def deactivate(self, account):
        if account.is_superadmin:
            '''Proceed with deactivating the company'''
            self.active_until = timezone.make_aware(
            datetime.now() - timedelta(days=90)
            )
            self.save()
        else:
            '''The user is not a superadmin, so do not allow them to deactivate the company'''
            raise PermissionError('Only superadmins can deactivate a company')

    class Meta:
        verbose_name_plural = 'Companies'
        constraints = [
            models.UniqueConstraint(fields=['admin'],
                                    name='unique_admin_user')
        ]
        
    def __str__(self) -> str:
        return self.name

class Invitation(Model):
    email = models.EmailField(max_length=255)
    accepted = models.BooleanField(default=False)
    invited_by = models.ForeignKey(
        Account, on_delete=models.CASCADE, related_name="invitations"
    )
    used = models.BooleanField(default=False)
    '''Accept invite function to call when user clicks on link in email'''
    def accept(self):
        self.accepted = True
        self.save()