from rest_framework.permissions import BasePermission

class IsCompanyAdmin(BasePermission):
    def has_permission(self, request, view):
        user = request.user
        return user and user.is_authenticated and user.is_companyadmin

class IsSuperAdmin(BasePermission):
    def has_permission(self, request, view):
        user = request.user
        return user and user.is_authenticated and user.is_superadmin

class IsSuperAdminOrCompanyAdmin(BasePermission):
    def has_permission(self, request, view):
        is_super_admin = IsSuperAdmin().has_permission(request, view)
        is_company_admin = IsCompanyAdmin().has_permission(request, view)
        return is_super_admin or is_company_admin