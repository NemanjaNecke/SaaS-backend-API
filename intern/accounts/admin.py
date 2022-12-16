from django.contrib import admin
from .models import Account, IPAddress, Company, Invitation
# Register your models here.
@admin.register(Account)
class AccountAdmin(admin.ModelAdmin):
    def company_list(self, obj):
        return ','.join([k.name for k in Company.objects.filter(accounts=obj.pk)])
    ordering = ['id']
    list_display = ['email', 'first_name', 'last_name', 'is_staff', 'company_list']
    list_filter = ['is_staff']

@admin.register(IPAddress)
class IPAddressAdmin(admin.ModelAdmin):
    list_display = ['ip_address', 'account', 'verified']

@admin.register(Company)
class CompanyAdmin(admin.ModelAdmin):
    def account_list(self, obj):
        return ",".join([k.email for k in Account.objects.filter(company=obj.pk)])
    list_display = ['name', 'admin', 'active_until', 'is_active', 'account_list']

@admin.register(Invitation)
class InviteAdmin(admin.ModelAdmin):
    list_display = ['email', 'accepted', 'invited_by']