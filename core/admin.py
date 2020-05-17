from django.contrib import admin

from . import models


class UserAdmin(admin.ModelAdmin):
    fieldsets = (
        (
            None,
            {
                "fields": (
                    "username",
                    "email",
                    "first_name",
                    "last_name",
                    "is_active",
                    "password",
                    "verified",
                )
            },
        ),
        ("Information if doctor", {"classes": ("collapse",), "fields": ("is_doctor",)}),
        (
            "Information if Patient",
            {"classes": ("collapse",), "fields": ("is_patient",)},
        ),
        (
            "Advanced options",
            {
                "classes": ("collapse",),
                "fields": ("groups", "is_staff", "date_joined", "user_permissions"),
            },
        ),
    )

    search_fields = ["id", "username", "email"]
    list_display = ("id", "username", "email", "is_patient", "is_doctor", "verified")
    list_display_links = (
        "id",
        "username",
        "email",
    )
    list_editable = (
        "verified",
        "is_patient",
        "is_doctor",
    )
    ordering = ("id",)

    class Meta:
        model = models.User


class ReportAdmin(admin.ModelAdmin):
    search_fields = ["id", "report_name"]
    list_display = (
        "id",
        "patient",
        "report_name",
    )
    list_display_links = (
        "id",
        "patient",
    )
    list_editable = ("report_name",)
    ordering = ("patient",)

    class Meta:
        model = models.Report


class ReportImageAdmin(admin.ModelAdmin):
    search_fields = ["id"]
    list_display = (
        "id",
        "report",
    )
    # list_display_links = ('id', 'patient',)
    ordering = ("report",)

    class Meta:
        model = models.ReportImage


class AssignDoctorAdmin(admin.ModelAdmin):
    search_fields = ["id"]
    list_display = (
        "id",
        "doctor",
    )
    list_display_links = (
        "id",
        "doctor",
    )
    ordering = ("id",)

    class Meta:
        model = models.AssignDoctor


class DoctorBookingDetailPerDayAdmin(admin.ModelAdmin):
    search_fields = ["id", "date", "start_time", "end_time"]
    list_display = (
        "id",
        "doctor",
        "date",
        "start_time",
        "end_time",
    )
    list_display_links = (
        "id",
        "doctor",
        "date",
    )
    ordering = ("id",)

    class Meta:
        model = models.DoctorBookingDetailPerDay


class PatientBookingDetailAdmin(admin.ModelAdmin):
    search_fields = ["id", "token_number"]
    list_display = (
        "id",
        "patient",
        "booking_slot",
        "token_number",
    )
    list_display_links = (
        "id",
        "patient",
        "booking_slot",
        "token_number",
    )
    ordering = ("id",)

    class Meta:
        model = models.PatientBookingDetail


admin.site.register(models.User, UserAdmin)
admin.site.register(models.Report, ReportAdmin)
admin.site.register(models.ReportImage, ReportImageAdmin)
admin.site.register(models.AssignDoctor, AssignDoctorAdmin)
admin.site.register(models.DoctorBookingDetailPerDay, DoctorBookingDetailPerDayAdmin)
admin.site.register(models.PatientBookingDetail, PatientBookingDetailAdmin)
admin.site.register(models.Profile)
