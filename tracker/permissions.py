"""
Custom DRF Permissions based on User Roles.

ADMIN  → full CRUD access
STAFF  → create, read, update; no delete
VIEWER → read-only
"""

from rest_framework.permissions import BasePermission


def get_user_role(user):
    """Helper to safely get the user's role string."""
    try:
        return user.profile.role
    except Exception:
        return 'viewer'


class IsAdminRole(BasePermission):
    """Only admin-role users are allowed."""
    def has_permission(self, request, view):
        return request.user.is_authenticated and get_user_role(request.user) == 'admin'


class IsStaffOrAdmin(BasePermission):
    """Staff and Admin users are allowed (not Viewer)."""
    def has_permission(self, request, view):
        return request.user.is_authenticated and get_user_role(request.user) in ('admin', 'staff')


class ReadOnlyOrStaffAdmin(BasePermission):
    """
    Read-only for all authenticated users.
    Write operations restricted to staff and admin.
    """
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        if request.method in ('GET', 'HEAD', 'OPTIONS'):
            return True  # All roles can read
        return get_user_role(request.user) in ('admin', 'staff')