"""
Forms for as_email.
"""
# system imports
#

from crispy_forms.helper import FormHelper
from crispy_forms.layout import Submit

# 3rd party imports
#
from django import forms

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
            "delivery_method",
            "autofile_spam",
            "spam_delivery_folder",
            "spam_score_threshold",
            "alias_for",
            # "aliases",
            "forward_to",
        ]

    ####################################################################
    #
    def __init__(self, *args, **kwargs):
        """
        Make the EmailAccountForm crispy.
        """
        super().__init__(*args, **kwargs)
        instance = kwargs["instance"]
        self.helper = FormHelper()
        self.helper.form_id = f"email-account-form-{instance.pk}"
        self.helper.form_class = "blueForms"
        self.helper.form_method = "post"
        self.helper.form_action = "as_email:email-account-detail"

        self.helper.add_input(Submit("submit", "Submit"))
