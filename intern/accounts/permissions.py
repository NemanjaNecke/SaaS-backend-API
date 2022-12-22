from rest_framework.permissions import BasePermission

class IsCompanyAdmin(BasePermission):
    def has_permission(self, request, view):
        user = request.user
        return user and user.is_authenticated and user.is_companyadmin

class IsSuperAdmin(BasePermission):
    def has_permission(self, request, view):
        user = request.user
        return user and user.is_authenticated and user.is_superadmin
