from django.contrib.auth import login, logout
from django.contrib.sites.shortcuts import get_current_site

from django.http import HttpResponse
from django.shortcuts import redirect
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.views.generic import ListView
from rest_framework import permissions
from rest_framework import status, viewsets, generics, mixins
from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.validators import ValidationError
from rest_framework.views import APIView

from .models import (
    Profile,
    User,
    Report,
    ReportImage,
    AssignDoctor,
    PatientBookingDetail,
    DoctorBookingDetailPerDay,
)
from .serializers import (
    DoctorBookingDetailPerDaySerializer,
    PatientBookingDetailSerializer,
    AssignDoctorSerializer,
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
from .custom_permissions import CreateAndIsAuthenticated, UserIsDoctor, UserIsPatient


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
        report = Report.objects.filter(pk=self.kwargs['report_pk']).prefetch_related('report_images')
        if len(report) == 0 or report[0].patient != self.request.user:
            return ValidationError("Not Found")
        return report[0].report_images.all()

    def perform_create(self, serializer):
        try:
            report = Report.objects.get(pk=self.kwargs['report_pk'])
            if report.patient != self.request.user:
                raise ValidationError("Not Found")
        except Exception as e:
            raise ValidationError("Not Found")

        result = "this is our opinion"
        # skin_image = serializer.validated_data["skin_image"]
        serializer.save(web_opinion=result, report=report)


class DoctorBookingDetailPerDayViewset(viewsets.ModelViewSet):
    """
        GET:-
            All slots of doctor
            Filter by ?date=yyyy-mm-dd
        POST:-
            Create slots by login doctor
    """

    serializer_class = DoctorBookingDetailPerDaySerializer
    queryset = DoctorBookingDetailPerDay.objects.all()
    permission_classes = (permissions.IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def get_queryset(self):
        if not self.request.user.is_doctor:
            raise ValidationError("You are not doctor")
        slots = DoctorBookingDetailPerDay.objects.all()
        slots = self.request.user.all_booking_slot.all()
        date = self.request.query_params.get("date", None)
        if date:
            slots = slots.filter(date=date)
        return slots

    def perform_create(self, serializer):
        if not self.request.user.is_doctor:
            raise ValidationError("You are not doctor")
        serializer.save(doctor=self.request.user)


class PatientBookingDetailViewset(viewsets.ModelViewSet):
    serializer_class = PatientBookingDetailSerializer
    permission_classes = (permissions.IsAuthenticated,)
    queryset = PatientBookingDetail.objects.all()
    authentication_classes = (TokenAuthentication,)

    def get_queryset(self):
        if not self.request.user.is_patient:
            raise ValidationError("You are not patient")
        return self.request.user.patient_booking.all()

    def get_serializer_context(self):
        return {"request": self.request}

    def perform_create(self, serializer):
        if not self.request.user.is_patient:
            raise ValidationError("You are not patient")
        print(serializer)
        serializer.save(patient=self.request.user, token=1)


class AssignDoctorViewset(viewsets.ModelViewSet):
    serializer_class = AssignDoctorSerializer
    permission_classes = (permissions.IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)
    queryset = AssignDoctor.objects.all()

    def get_queryset(self):
        """
            GET:
                ?report_id=x&doctor_id=y

            POST:
                only create
                 1. when doctor is proper doctor
                 2. patient is login user
        """
        if not self.request.user.is_patient:
            raise ValidationError("You are not patient")
        report_id = self.request.query_params.get("report_id", None)
        doctor_id = self.request.query_params.get("doctor_id", None)
        queryset = AssignDoctor.objects.all()
        if report_id is not None:
            try:
                report = Report.objects.get(id=report_id)
                if not report.patient.is_patient:
                    raise ValidationError("Invalid report")
            except Report.DoesNotExist:
                raise ValidationError("Please provide valid report")

            queryset = queryset.filter(assign_report=report_id)

        if doctor_id is not None:
            try:
                doctor = User.objects.get(id=doctor_id)
                if not doctor.is_doctor:
                    raise ValidationError("Invalid doctor")
            except User.DoesNotExist:
                raise ValidationError("Invalid Doctor")
            queryset = queryset.filter(doctor_id=doctor_id)
        return queryset

    def perform_create(self, serializer):
        if not self.request.user.is_patient:
            raise ValidationError("You are not patient")

        doctor = serializer.validated_data["doctor"]
        report = serializer.validated_data["assign_report"]

        try:
            _ = Report.objects.get(id=report.id)
        except Report.DoesNotExist:
            raise ValidationError("Please provide valid report")
        try:
            _ = User.objects.get(id=doctor.id)
        except User.DoesNotExist:
            raise ValidationError("Please provide valid doctor")

        if not doctor.is_doctor:
            raise ValidationError("Your Doctor is not a doctor")
        # serializer.save(assign_report=report, doctor=doctor)
        if report.patient is self.request.user:
            serializer.save(assign_report=report, doctor=doctor)
        else:
            raise ValidationError("You are not authorized")


class ProfileViewSet(viewsets.ModelViewSet):
    """
    update user profile and display
    """

    authentication_classes = (TokenAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = ProfileSerializer
    queryset = Profile.objects.all()

    # def perform_create(self, serializer):
    #     serializer.save(user=self.request.user)


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

