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
        account.is_superadmin = True
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
    date_joined = models.DateTimeField(default=timezone.make_aware(datetime.now()))
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

    def activate(self, account):
        if account.is_superadmin:
            '''Proceed with activating the company'''
            self.active_until = timezone.make_aware(
            datetime.now() + timedelta(days=90)
            )
            self.save()
        else:
            '''The user is not a superadmin, so do not allow them to activate the company'''
            raise PermissionError('Only superadmins can activate a company')

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

class Task(Model):
    STATUS_CHOICES = (
        ('open', 'Opened'),
        ('assigned', 'Assigned'),
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('error_open', 'Closed opened in error')
    )
    CURRENCY_CHOICES = (
        ('EUR', 'EURO'),
        ('USD', 'American Dolar'),
        ('RUB', 'Russian ruble'),
        ('BAM', 'Bosnia and Herzegovina convertible mark'),
        ('RSD', 'Serbian Dinar')
    )
    PRIORITY_CHOICES = (
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High')
    )
    CATEGORY_CHOICES = (
        ('sales', 'Sales'),
        ('marketing', 'Marketing'),
        ('finance', 'Finance'),
        ('tech', 'Technology'),
        ('hr', 'Human Resources')
    )
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name='company')
    description = models.CharField(max_length=500)
    due_date = models.DateTimeField(default=timezone.make_aware(datetime.now() + timedelta(days=1)))
    status = models.CharField(max_length=30, choices=STATUS_CHOICES)
    value = models.DecimalField(max_digits=10, decimal_places=2)
    priority = models.CharField(max_length=10, choices=PRIORITY_CHOICES, default='EDIT')
    currency = models.CharField(max_length=3, choices=CURRENCY_CHOICES)
    responsible_user = models.ForeignKey(Account, on_delete=models.CASCADE, related_name='tasks_responsible')
    created_by = models.ForeignKey(Account, on_delete=models.CASCADE, related_name='tasks_created')
    notification = models.BooleanField(default=True)
    notification_date = models.DateTimeField(null=True,blank=True,default=timezone.make_aware(datetime.now() + timedelta(days=3)))
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES, default='EDIT')