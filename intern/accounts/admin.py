from django.contrib import admin
from .models import Account, IPAddress, Company, Invitation, Task

from django import forms
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.models import Group
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.forms import ReadOnlyPasswordHashField
from django.core.exceptions import ValidationError
# Register your models here.
class UserCreationForm(forms.ModelForm):
    """A form for creating new users. Includes all the required
    fields, plus a repeated password."""
    password1 = forms.CharField(label='Password', widget=forms.PasswordInput)
    password2 = forms.CharField(label='Password confirmation', widget=forms.PasswordInput)

    class Meta:
        model = Account
        fields = ('email', 'first_name', 'last_name', 'is_staff', 'company', 'is_companyadmin', 'is_superadmin')

    def clean_password2(self):
        # Check that the two password entries match
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise ValidationError("Passwords don't match")
        return password2

    def save(self, commit=True):
        # Save the provided password in hashed format
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user


class UserChangeForm(forms.ModelForm):
    """A form for updating users. Includes all the fields on
    the user, but replaces the password field with admin's
    disabled password hash display field.
    """
    change_password_form = PasswordChangeForm
    password = ReadOnlyPasswordHashField(label=("Password"),
        help_text=("Raw passwords are not stored, so there is no way to see "
                    "this user's password, but you can change the password "
                    "using <a href=\"../password/\">this form</a>."))

    class Meta:
        model = Account
        fields = ('email', 'password',  'is_active', 'is_companyadmin', 'is_superadmin')


class UserAdmin(BaseUserAdmin):
    # The forms to add and change user instances
    form = UserChangeForm
    add_form = UserCreationForm

    # The fields to be used in displaying the User model.
    # These override the definitions on the base UserAdmin
    # that reference specific fields on auth.User.
    list_display = ('email', 'first_name', 'last_name', 'is_active', 'is_staff', 'is_companyadmin', 'is_superadmin', 'company', 'date_joined', 'last_login')
    list_filter = ('email',)
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name',)}),
        ('Permissions', {'fields': ('is_companyadmin', 'is_superadmin', 'is_staff')}),
    )
    # add_fieldsets is not a standard ModelAdmin attribute. UserAdmin
    # overrides get_fieldsets to use this attribute when creating a user.
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'first_name', 'last_name', 'is_active', 'is_staff', 'is_companyadmin', 'is_superadmin', 'company', 'date_joined', 'last_login'),
        }),
    )
    search_fields = ('email',)
    ordering = ('email',)
    filter_horizontal = ()


# Now register the new UserAdmin...
admin.site.register(Account, UserAdmin)

admin.site.unregister(Group)
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
    list_display = ['email', 'accepted', 'invited_by', 'used']

@admin.register(Task)
class TaskAdmin(admin.ModelAdmin):
    list_display = ('company', 'description', 'due_date', 'status', 'value', 'currency', 'responsible_user', 'created_by')