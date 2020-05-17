from rest_framework import permissions


class CreateAndIsAuthenticated(permissions.IsAuthenticated):
    def has_permission(self, request, view):
        return view.action == "create" or super(
            CreateAndIsAuthenticated, self
        ).has_permission(request, view)


class UserIsPatient(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_patient


class UserIsDoctor(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_doctor
