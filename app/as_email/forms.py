"""
Forms for as_email.
"""

# system imports
#

# 3rd party imports
#
from crispy_forms.helper import FormHelper
from django import forms
from django.urls import reverse

# project imports
#
from .models import EmailAccount


########################################################################
########################################################################
#
class EmailAccountForm(forms.ModelForm):
    class Meta:
        model = EmailAccount
        fields = [
            "enabled",
        ]

    ####################################################################
    #
    def __init__(self, *args, **kwargs):
        """
        Make the EmailAccountForm crispy.
        """
        super().__init__(*args, **kwargs)
        self.helper = FormHelper(self)
        if self.instance and self.instance.pk:
            self.helper.form_id = f"email-account-form-{self.instance.pk}"
            self.helper.form_action = reverse(
                "as_email:email-account-detail",
                kwargs={"pk": self.instance.pk},
            )
        else:
            self.helper.form_id = "new-email-account-form-id"
            self.helper.form_action = "as_email:email-account-list"
        self.helper.form_method = "post"
        self.helper.form_class = "content"
        self.helper.form_horizontal = True
