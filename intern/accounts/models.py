from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from utils.model_abstracts import Model

class AccountManager(BaseUserManager):

    def create_account(self, email, password, **extrafields):
        if not email:
            raise ValueError('Users must have an email address')
        user = self.model(email=self.normalize_email(email), password=password, **extrafields)
        user.set_password(password)
        user.save(using=self.db)

        return user


    def create_superuser(self, email, password):
        user = self.create_account(email=self.normalize_email(email), password=password)
        user.is_staff = True
        user.is_admin = True
        user.is_superuser = True
        user.save(using=self.db)

        return user


class Account(AbstractBaseUser, Model, PermissionsMixin):
    email = models.EmailField(max_length=255, unique=True)
    username = models.CharField(max_length=255, null=True, blank=True)
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = AccountManager()

    USERNAME_FIELD = 'email'
    EMAIL_FIELD = 'email'

class IPAddress(Model):
    ip_address = models.GenericIPAddressField(protocol='both', unpack_ipv4=True)
    account = models.ForeignKey(Account, on_delete=models.CASCADE, related_name='ip_address')

    class Meta:
        verbose_name_plural = 'IPAddresses'
    def __str__(self) -> str:
        return self.ip_address