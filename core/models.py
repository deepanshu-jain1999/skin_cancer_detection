from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone

from .choices import *


class User(AbstractUser):
    city = models.CharField(max_length=50, default="delhi")
    gender = models.IntegerField(choices=GENDER_CHOICES, default=1)
    qualification = models.CharField(max_length=100, blank=True)
    verified = models.BooleanField(default=False)
    registration_number = models.CharField(max_length=15, blank=True)
    is_patient = models.BooleanField(default=False)
    is_doctor = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)

    def __str__(self):
        return self.username


class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    photo = models.ImageField(upload_to="User_Profile/%Y-%m-%d", blank=True)
    date_of_birth = models.DateField(default=timezone.now)
    city = models.CharField(max_length=50, default="delhi")
    gender = models.IntegerField(choices=GENDER_CHOICES, default=1)
    qualification = models.CharField(max_length=100, blank=True)
    registration_number = models.CharField(max_length=15, blank=True)

    def __str__(self):
        return self.user.username


class Report(models.Model):
    report_name = models.CharField(max_length=100)
    patient = models.ForeignKey(User, on_delete=models.CASCADE, related_name="report")

    class Meta:
        unique_together = (
            "report_name",
            "patient",
        )

    def __str__(self):
        return (
            "Patient Name:- '"
            + self.patient.username
            + "'    Report Name:- '"
            + self.report_name
            + "'"
        )


class AssignDoctor(models.Model):
    opinion = models.TextField(blank=True)
    doctor = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="assign_doctor"
    )
    assign_report = models.ForeignKey(
        Report, on_delete=models.CASCADE, related_name="assign_report"
    )

    def __str__(self):
        return "Doctor Name:- " + self.doctor.username

    class Meta:
        unique_together = (
            "assign_report",
            "doctor",
        )


class ReportImage(models.Model):
    skin_image = models.ImageField(upload_to="Patient/%Y-%m-%d")
    web_opinion = models.TextField(blank=True)
    report = models.ForeignKey(
        Report, on_delete=models.CASCADE, related_name="report_images"
    )

    def __str__(self):
        return (
            "Patient Name:- "
            + self.report.patient.username
            + "   Report Name:- "
            + self.report.report_name
        )


class DoctorBookingDetailPerDay(models.Model):
    doctor = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="all_booking_slot"
    )
    date = models.DateField()
    start_time = models.TimeField()
    end_time = models.TimeField()
    patient_per_hour = models.IntegerField(default=10)
    token_used = models.IntegerField(default=0)
    max_token = models.IntegerField(default=10)

    class Meta:
        unique_together = (
            "date",
            "doctor",
        )

    def __str__(self):
        return f"Doctor: {self.doctor} and Date: {self.date}"


class PatientBookingDetail(models.Model):
    patient = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="patient_booking"
    )
    token_number = models.IntegerField(default=1)
    booking_slot = models.ForeignKey(
        DoctorBookingDetailPerDay, related_name="appointment", on_delete=models.CASCADE
    )

    class Meta:
        unique_together = (
            "patient",
            "booking_slot",
        )

    def __str__(self):
        return self.patient.username
