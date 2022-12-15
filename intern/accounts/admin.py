from django.contrib import admin
from .models import Account, IPAddress, Company, Invitation
# Register your models here.
@admin.register(Account)
class AccountAdmin(admin.ModelAdmin):
    ordering = ['id']
    list_display = ['email', 'first_name', 'last_name', 'is_staff']
    list_filter = ['is_staff']

@admin.register(IPAddress)
class IPAddressAdmin(admin.ModelAdmin):
    list_display = ['ip_address', 'account', 'verified']

@admin.register(Company)
class CompanyAdmin(admin.ModelAdmin):
    list_display = ['name', 'admin', 'active_until', 'is_active', 'accounts']

@admin.register(Invitation)
class InviteAdmin(admin.ModelAdmin):
    list_display = ['email', 'accepted', 'invited_by']