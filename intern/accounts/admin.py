from django.contrib import admin
from .models import Account, IPAddress
# Register your models here.
@admin.register(Account)
class AccountAdmin(admin.ModelAdmin):
    pass

@admin.register(IPAddress)
class IPAddressAdmin(admin.ModelAdmin):
    list_display = ['ip_address', 'account']