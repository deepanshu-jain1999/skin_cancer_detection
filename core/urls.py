from django.urls import path, include, re_path
from rest_framework import routers

from . import views

router = routers.DefaultRouter()
router.register(r"users", views.UserViewSet, basename="user")
router.register(r"report", views.ReportViewset)
router.register(r"report-images", views.ReportImagesViewset, basename="report-images")
router.register(r"assign-doctor", views.AssignDoctorViewset, basename="assign-doctor")
router.register(
    r"booking-slots-doctor",
    views.DoctorBookingDetailPerDayViewset,
    basename="booking-slots",
)
router.register(
    r"booking-of-patient",
    views.PatientBookingDetailViewset,
    basename="booking-of-patient",
)

urlpatterns = [
    path("", include(router.urls)),
    path("signup/", views.Signup.as_view()),
    path("login/", views.Login.as_view()),
    re_path(
        r"^activate_user/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]+)/$",
        views.Activate.as_view(),
        name="activate",
    ),
    path("logout/", views.Logout.as_view()),
    path("profile/", views.UserProfile.as_view()),
    path("profile/<int:id>", views.SeeProfile.as_view()),
    path("doctors-list/", views.DoctorListView.as_view()),
]
