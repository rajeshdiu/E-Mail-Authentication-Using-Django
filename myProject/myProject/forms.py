from django import forms
from django.contrib.auth.forms import PasswordResetForm
from django.utils.translation import gettext_lazy as _

class CustomPasswordResetForm(PasswordResetForm):
    email = forms.EmailField(label=_("Email"), max_length=254)

    def clean_email(self):
        email = self.cleaned_data.get('email')
        # You can add additional checks here if necessary
        return email
