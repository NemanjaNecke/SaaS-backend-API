from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import PasswordResetTokenGenerator
import six


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
        'domain': 'http://localhost:4200',
        'uid': urlsafe_base64_encode(force_bytes(email+'/'+str(company.pk))),
        'token': registration_activation_token.make_token(email),
        'protocol': 'https' if request.is_secure() else 'http'
    })
    email = EmailMessage(mail_subject, message, to=[email])
    email.send()

def activate_ip(request, email, ip_address):
    mail_subject = 'Activate your new IP address.'
    message = render_to_string('account/email/ip_verification_message.html', {
        'user': email,
        'domain': get_current_site(request).domain,
        'uid': urlsafe_base64_encode(force_bytes(email+'-' + ip_address)),
        'token': account_activation_token.make_token(email),
        'protocol': 'https' if request.is_secure() else 'http'
    })
    email = EmailMessage(mail_subject, message, to=[email])
    email.send()

