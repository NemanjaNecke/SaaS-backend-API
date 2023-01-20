
from datetime import timedelta
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import PasswordResetTokenGenerator
import six
from django.utils import timezone
from .models import Task, Account

class AccountActivationTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, email, timestamp):
        return (
            six.text_type(email) + six.text_type(timestamp)
        )

account_activation_token = AccountActivationTokenGenerator()
registration_activation_token = AccountActivationTokenGenerator()

def send_registration_invite(request, email, company, admin):
    mail_subject = 'This is your invatation to register for {}'.format(company)
    message = render_to_string('account/email/register_invite.html',{
        'account': email,
        'admin': admin,
        'company': company.name,
        'domain': 'https://admin-intern.firebaseapp.com/',
        'uid': urlsafe_base64_encode(force_bytes(email+'/'+str(company.pk))),
        'token': registration_activation_token.make_token(email),
        'protocol': 'https' if request.is_secure() else 'http'
    })
    email = EmailMessage(mail_subject, message, to=[email])
    email.send()

def activate_ip(request, email, ip_address):
    user = Account.objects.get(email=email)
    mail_subject = 'Activate your new IP address.'
    message = render_to_string('account/email/ip_verification_message.html', {
        'user': user,
        'domain': get_current_site(request).domain,
        'uid': urlsafe_base64_encode(force_bytes(email+'-' + ip_address)),
        'token': account_activation_token.make_token(email),
        'protocol': 'https' if request.is_secure() else 'http'
    })
    email = EmailMessage(mail_subject, message, to=[email])
    email.content_subtype = "html"
    email.send()

def send_notification_expiration_email(request):
    now = timezone.now()
    tasks = Task.objects.filter(notification=True, notification_date__lte=now + timedelta(hours=6))

    for task in tasks:
        subject = 'Notification expiration for task: {}'.format(task.description)
        message = render_to_string('account/email/notification_expiration.html', {
            'task': task,
            'protocol': 'https' if request.is_secure() else 'http',
            'domain': get_current_site(request).domain})
        to_email = task.responsible_user.email
        email = EmailMessage(subject, message, to=[to_email])
        email.content_subtype = "html"
        email.send()