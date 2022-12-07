from django.contrib import admin
from .models import Account, IPAddress
# Register your models here.
@admin.register(Account)
class AccountAdmin(admin.ModelAdmin):
    ordering = ['id']
    list_display = ['email', 'username', 'first_name', 'last_name', 'is_staff']
    list_filter = ['is_staff']

@admin.register(IPAddress)
class IPAddressAdmin(admin.ModelAdmin):
    list_display = ['ip_address', 'account', 'verified']