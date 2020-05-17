from django.contrib.auth import authenticate
from django.contrib.auth.hashers import make_password
from rest_framework import serializers
from rest_framework.validators import UniqueValidator

from .models import AssignDoctor
from .models import (
    User,
    Profile,
    Report,
    ReportImage,
    DoctorBookingDetailPerDay,
    PatientBookingDetail,
)


class PasswordSerializer(serializers.Serializer):
    """
    Serializer for password change endpoint.
    """

    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)


class ProfileSerializer(serializers.ModelSerializer):
    user = serializers.HiddenField(default=serializers.CurrentUserDefault())

    class Meta:
        model = Profile
        fields = "__all__"


class UserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        required=True, validators=[UniqueValidator(queryset=User.objects.all())]
    )
    username = serializers.CharField(
        max_length=100, validators=[UniqueValidator(queryset=User.objects.all())]
    )
    profile = ProfileSerializer(required=False)

    class Meta:
        model = User
        fields = [
            "id",
            "username",
            "email",
            "is_doctor",
            "is_patient",
            "profile",
            "password",
        ]
        extra_kwargs = {"password": {"write_only": True}}

    def create(self, validated_data):
        validated_data["password"] = make_password(validated_data["password"])
        user = User.objects.create(**validated_data)
        return user


class LoginSerializer(serializers.Serializer):
    user = serializers.CharField(max_length=100)
    password = serializers.CharField(min_length=8)

    def validate(self, attrs):
        user_email = attrs.get("user")
        password = attrs.get("password")
        if user_email and password:
            user = authenticate(username=user_email, password=password)
            if user:
                if not user.is_active:
                    message = "Not a valid user"
                    raise serializers.ValidationError(message)
            else:
                message = "Not matching username and password"
                raise serializers.ValidationError(message)
        else:
            message = "Include both username and  password"
            raise serializers.ValidationError(message, )
        attrs["user"] = user
        return attrs


class AssignDoctorByPatientSerializer(serializers.ModelSerializer):
    assign_report = serializers.CharField(default=None, allow_null=True)

    class Meta:
        model = AssignDoctor
        fields = "__all__"
        extra_kwargs = {"opinion": {"read_only": True}}

    def get_validation_exclusions(self):
        exclusions = super(
            AssignDoctorByPatientSerializer, self
        ).get_validation_exclusions()
        return exclusions + ["assign_report"]


class AssignReportToDoctorSerializer(serializers.ModelSerializer):
    doctor = serializers.HiddenField(default=serializers.CurrentUserDefault())
    assign_report = serializers.CharField(default=None, allow_null=True)

    class Meta:
        model = AssignDoctor
        fields = "__all__"


class ReportImageSerializer(serializers.ModelSerializer):
    report = serializers.CharField(required=False)

    class Meta:
        model = ReportImage
        fields = "__all__"


class ReportSerializer(serializers.ModelSerializer):
    patient = serializers.HiddenField(default=serializers.CurrentUserDefault())
    assign_doctors = AssignDoctorByPatientSerializer(
        "assign_doctor", many=True, required=False
    )
    report_images = ReportImageSerializer("report_images", many=True, required=False)

    class Meta:
        model = Report
        fields = "__all__"


class PatientBookingDetailSerializer(serializers.ModelSerializer):
    patient = serializers.HiddenField(default=serializers.CurrentUserDefault())

    class Meta:
        model = PatientBookingDetail
        fields = "__all__"
        extra_kwargs = {"token_number": {"read_only": True}}


class DoctorBookingDetailPerDaySerializer(serializers.ModelSerializer):
    doctor = serializers.HiddenField(default=serializers.CurrentUserDefault())
    appointments = PatientBookingDetailSerializer(
        "booking_slot", many=True, required=False
    )

    class Meta:
        model = DoctorBookingDetailPerDay
        fields = "__all__"
