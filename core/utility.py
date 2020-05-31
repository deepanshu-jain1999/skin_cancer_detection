from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from django.conf import settings


def email_send(user, username, email, current_site, text, token):
    message = "hello how are you"
    msg_html = render_to_string(
        "core/email_template.html",
        {
            "user": username,
            "domain": current_site.domain,
            "uid": urlsafe_base64_encode(force_bytes(user.pk)),
            "token": token,
            "text": text,
        },
    )
    subject = "Activate your account"
    from_mail = settings.EMAIL_HOST_USER
    to_mail = [email]
    return send_mail(
        subject, message, from_mail, to_mail, html_message=msg_html, fail_silently=False
    )


def check_token(user, token):
    user_token = user.auth_token.key
    if user_token == token:
        return True
    return False
