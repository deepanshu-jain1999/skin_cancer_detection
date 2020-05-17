from django.urls import path, include, re_path
from rest_framework_nested import routers

from . import views

router = routers.SimpleRouter()
router.register(r"users", views.UserViewSet, basename="user")
router.register(r"profile", views.ProfileViewSet, basename="profile")
router.register(
    r"assign-report", views.AssignReportToDoctorViewset, basename="assign-report"
)
router.register(r"report", views.ReportViewset, basename="report")
report_router = routers.NestedSimpleRouter(router, r"report", lookup="report")
report_router.register(
    r"report-images", views.ReportImagesViewset, basename="report-images"
)
report_router.register(
    r"assign-doctor", views.AssignDoctorByPatientViewset, basename="assign-doctor"
)
# router.register(r"assign-doctor", views.AssignDoctorViewset, basename="assign-doctor")
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
    path("", include(report_router.urls)),
    path("login/", views.Login.as_view(), name="login"),
    re_path(
        r"^activate_user/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]+)/$",
        views.Activate.as_view(),
        name="activate",
    ),
    path("logout/", views.Logout.as_view(), name="logout"),
    path("doctors-list/", views.DoctorListView.as_view(), name="doctors_list"),
]
