from django.contrib.auth import login, logout
from django.contrib.sites.shortcuts import get_current_site
from django.http import HttpResponse
from django.shortcuts import redirect
from django.utils.encoding import force_text
from django.utils.http import urlsafe_base64_decode
from rest_framework import permissions
from rest_framework import status, viewsets, generics
from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.validators import ValidationError
from rest_framework.views import APIView

from .custom_permissions import CreateAndIsAuthenticated, UserIsDoctor, UserIsPatient
from .models import (
    Profile,
    User,
    Report,
    PatientBookingDetail,
    DoctorBookingDetailPerDay,
)
from .serializers import (
    DoctorBookingDetailPerDaySerializer,
    PatientBookingDetailSerializer,
    AssignDoctorByPatientSerializer,
    AssignReportToDoctorSerializer,
)
from .serializers import (
    LoginSerializer,
    ProfileSerializer,
    ReportSerializer,
    ReportImageSerializer,
    PasswordSerializer,
)
from .serializers import UserSerializer
from .utility import email_send, check_token


def get_cancer_name():
    cancer_list = ["Melanocytic Nevi",
                   "Melanoma",
                   "Benign Keratosis",
                   "Basal Cell Carcinoma",
                   "Actinic Keratoses",
                   "Vascular Lesions",
                   "Dermatofibroma",
                   ]
    from random import randrange
    ind = randrange(len(cancer_list))
    return cancer_list[ind]


class DoctorListView(generics.ListAPIView):
    serializer_class = UserSerializer
    paginate_by = 5
    doctors = User.objects.filter(is_doctor=True, verified=True)

    def city_filter(self, city):
        if city:
            self.doctors = self.doctors.filter(profile__city__icontains=city)

    def registration_number_filter(self, number):
        if number:
            self.doctors = self.doctors.filter(
                profile__registration_number__icontains=number
            )

    def gender_filter(self, gender):
        if gender:
            self.doctors = self.doctors.filter(profile__gender__icontains=gender)

    # def assigned_filter(self, report_id, assigned):
    #     if not report_id:
    #         return
    #     report = None
    #     try:
    #         report = Report.objects.get(id=report_id)
    #     except Report.DoesNotExist:
    #         raise ValidationError("Invalid report")
    #     assign_doctors = report.assign_report.all()
    #     if assigned:
    #         self.doctors = None
    #         for obj in assign_doctors:
    #             self.doctors += obj.doctor
    #     else:
    #         self.doctors = User.objects.exclude()

    def get_queryset(self):
        param = self.request.query_params
        self.city_filter(param.get("city", None))
        self.registration_number_filter(param.get("registration_number", None))
        self.gender_filter(param.get("gender", None))
        # self.assigned_filter(param.get('report_id', None), param.get('assign', None))
        return self.doctors


class DoctorBookingDetailPerDayViewset(viewsets.ModelViewSet):
    serializer_class = DoctorBookingDetailPerDaySerializer
    permission_classes = (permissions.IsAuthenticated, UserIsDoctor)
    authentication_classes = (TokenAuthentication,)

    def get_queryset(self):
        return self.request.user.all_booking_slot.all()


class PatientBookingDetailViewset(viewsets.ModelViewSet):
    serializer_class = PatientBookingDetailSerializer
    permission_classes = (permissions.IsAuthenticated, UserIsPatient)
    queryset = PatientBookingDetail.objects.all()
    authentication_classes = (TokenAuthentication,)

    def get_queryset(self):
        return self.request.user.patient_booking.all()

    def get_serializer_context(self):
        return {"request": self.request}

    def perform_create(self, serializer):
        booking_slot = self.request.data["booking_slot"]
        try:
            booking_slot_object = DoctorBookingDetailPerDay.objects.get(
                id=booking_slot
            )
        except Exception as e:
            raise ValidationError("Not Found")
        token_used = booking_slot_object.token_used
        serializer.save(token_number=token_used + 1)
        booking_slot_object.token_used = token_used + 1
        booking_slot_object.save()


class ReportViewset(viewsets.ModelViewSet):
    """
        GET, POST, PUT, DELETE,
    """

    permission_classes = (permissions.IsAuthenticated, UserIsPatient)
    authentication_classes = (TokenAuthentication,)
    serializer_class = ReportSerializer
    queryset = Report.objects.all()

    def get_queryset(self):
        return self.request.user.report.all()

    @action(detail=True)
    def report_images(self, request, pk=None):
        report = self.get_object()
        return report.report_images.all()


class ReportImagesViewset(viewsets.ModelViewSet):
    serializer_class = ReportImageSerializer
    permission_classes = (permissions.IsAuthenticated, UserIsPatient)
    authentication_classes = (TokenAuthentication,)

    def get_queryset(self):
        report = Report.objects.filter(pk=self.kwargs["report_pk"]).prefetch_related(
            "report_images"
        )
        if len(report) == 0 or report[0].patient != self.request.user:
            return ValidationError("Not Found")
        return report[0].report_images.all()

    def perform_create(self, serializer):
        try:
            report = Report.objects.get(pk=self.kwargs["report_pk"])
            if report.patient != self.request.user:
                raise ValidationError("Not Found")
        except Exception as e:
            raise ValidationError("Not Found")

        result = get_cancer_name()
        # skin_image = serializer.validated_data["skin_image"]
        serializer.save(web_opinion=result, report=report)


class AssignDoctorByPatientViewset(viewsets.ModelViewSet):
    serializer_class = AssignDoctorByPatientSerializer
    permission_classes = (permissions.IsAuthenticated, UserIsPatient)
    authentication_classes = (TokenAuthentication,)

    def get_queryset(self):
        report = Report.objects.filter(pk=self.kwargs["report_pk"]).prefetch_related(
            "assign_report"
        )
        if len(report) == 0 or report[0].patient != self.request.user:
            return ValidationError("Not Found")
        return report[0].assign_report.all()

    def perform_create(self, serializer):
        try:
            report = Report.objects.get(pk=self.kwargs["report_pk"])
            if report.patient != self.request.user:
                raise ValidationError("Not Found")
        except Exception as e:
            raise ValidationError("Not Found")
        doctor = serializer.validated_data["doctor"]
        if not doctor.is_doctor:
            raise ValidationError("Not Found")
        serializer.save(assign_report=report)


class AssignReportToDoctorViewset(viewsets.ModelViewSet):
    serializer_class = AssignReportToDoctorSerializer
    permission_classes = (permissions.IsAuthenticated, UserIsDoctor)
    authentication_classes = (TokenAuthentication,)

    def get_queryset(self):
        return self.request.user.assign_doctor.all()


class ProfileViewSet(viewsets.ModelViewSet):
    """
    update user profile and display
    """

    authentication_classes = (TokenAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = ProfileSerializer
    queryset = Profile.objects.all()


class Activate(APIView):
    def get(self, request, *args, **kwargs):
        try:
            uidb = kwargs["uidb64"]
            uid = force_text(urlsafe_base64_decode(uidb))
            user = User.objects.get(pk=uid)
        except Exception as e:
            user = None
        if user is not None and check_token(user, self.kwargs["token"]):
            user.is_active = True
            Profile.objects.get_or_create(user=user)
            user.save()
            return redirect("login")
        else:
            return HttpResponse("Invalid token")


class UserViewSet(viewsets.ModelViewSet):
    """
    A viewset for viewing and editing user instances.
    """

    serializer_class = UserSerializer
    queryset = User.objects.all()
    permission_classes = (CreateAndIsAuthenticated,)

    def perform_create(self, serializer):
        user = serializer.save()
        if user:
            token = Token.objects.create(user=user)
            json = serializer.data
            username = json["username"]
            email = json["email"]
            current_site = get_current_site(self.request)
            text = "Please Activate Your Account By clicking below :"
            email_send(user, username, email, current_site, text, token.key)
            return dict({"Detail": "User Created,  Please verify your email"})

    @action(detail=True, methods=["GET", "PUT"])
    def set_password(self, request, pk=None):
        if not request.user.is_authenticated:
            return Response({"Detail: Not Found"}, status=status.HTTP_404_NOT_FOUND)
        user = self.get_object()
        serializer = PasswordSerializer(data=request.data)

        if serializer.is_valid():
            if not user.check_password(serializer.data.get("old_password")):
                return Response(
                    {"old_password": ["Wrong password."]},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            user.set_password(serializer.data.get("new_password"))
            user.save()
            return Response({"status": "password set"}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class Login(APIView):
    serializer_class = LoginSerializer

    def post(
            self, format=None, **kwargs,
    ):
        serializer = self.serializer_class(data=self.request.data)
        if serializer.is_valid():
            user = serializer.validated_data["user"]
            login(self.request, user)
            return Response({"token": user.auth_token.key}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_401_UNAUTHORIZED)


class Logout(APIView):
    def get(self, request, *args, **kwargs):
        logout(request)
        return Response(
            {"message": "successfully logged out"}, status=status.HTTP_200_OK
        )
