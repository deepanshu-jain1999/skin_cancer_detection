from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from .models import (
    User,
    Profile,
    Report,
    ReportImage,
    DoctorBookingDetailPerDay,
    PatientBookingDetail,
)
from .models import AssignDoctor
from django.contrib.auth import authenticate, login
from django.contrib.auth.hashers import make_password
from rest_framework.validators import ValidationError
from rest_framework.authtoken.models import Token
from django.contrib.sites.shortcuts import get_current_site
from .utility import email_send


class PasswordSerializer(serializers.Serializer):
    """
    Serializer for password change endpoint.
    """

    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)


class ProfileSerializer(serializers.ModelSerializer):
    user = serializers.HiddenField(
        default=serializers.CurrentUserDefault()
    )

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
        fields = ["id", "username", "email", "is_doctor", "is_patient", "profile", "password"]
        extra_kwargs = {'password': {'write_only': True}}

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
            raise serializers.ValidationError(message,)
        attrs["user"] = user
        return attrs


class AssignDoctorSerializer(serializers.ModelSerializer):
    class Meta:
        model = AssignDoctor
        fields = "__all__"


class ReportImageSerializer(serializers.ModelSerializer):
    # report = serializers.ReadOnlyField()

    class Meta:
        model = ReportImage
        fields = "__all__"


class ReportSerializer(serializers.ModelSerializer):
    patient = serializers.ReadOnlyField(source="user.username")
    assign_doctors = AssignDoctorSerializer("assign_doctor", many=True, required=False)
    report_images = ReportImageSerializer("report_images", many=True, required=False)

    class Meta:
        model = Report
        fields = "__all__"


class PatientBookingDetailSerializer(serializers.ModelSerializer):
    patient = serializers.ReadOnlyField(source="user.username")
    token_number = serializers.ReadOnlyField()

    def create(self, validated_data):
        booking_slot = validated_data["booking_slot"]
        try:
            booking_slot_object = DoctorBookingDetailPerDay.objects.get(
                id=booking_slot.id
            )
        except DoctorBookingDetailPerDay.DoesNotExist:
            raise ValidationError("Please provide valid Booking details")
        token_used = booking_slot_object.token_used
        request = self.context.get("request")
        patient = request.user
        slot = PatientBookingDetail.objects.create(
            patient=patient,
            token_number=token_used + 1,
            booking_slot_id=booking_slot.id,
        )
        booking_slot_object.token_used = token_used + 1
        booking_slot_object.save()
        return slot

    class Meta:
        model = PatientBookingDetail
        fields = "__all__"


class DoctorBookingDetailPerDaySerializer(serializers.ModelSerializer):
    doctor = serializers.ReadOnlyField(source="user.username")
    all_booking = PatientBookingDetailSerializer(source="appointment", many=True)

    class Meta:
        model = DoctorBookingDetailPerDay
        fields = "__all__"
