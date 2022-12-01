from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
# Create your models here.


class AccountManager(BaseUserManager):

    def create_account(self, email, username,first_name, last_name, password=None, **extrafields):
        if not email:
            raise ValueError('Users must have an email address')
        user = self.model(email=self.normalize_email(email), username=username,**extrafields)
        user.set_password(password)
        user.save(using=self.db)

        return user


    def create_superuser(self, email, password):
        user = self.create_account(email,password)
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self.db)

        return user


class Account(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(max_length=255, unique=True)
    username = models.CharField(max_length=255)
    name = models.CharField(max_length=255)

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = AccountManager()

    USERNAME_FIELD = 'email'


class IPAddress(models.Model):
    ip_address = models.GenericIPAddressField(protocol='both', unpack_ipv4=True)
    account = models.ForeignKey(Account, on_delete=models.CASCADE)

    class Meta:
        verbose_name_plural = 'IPAddresses'