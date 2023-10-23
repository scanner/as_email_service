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
    aliases = forms.ModelMultipleChoiceField(queryset=None)
    alias_for = forms.ModelMultipleChoiceField(queryset=None)

    class Meta:
        model = EmailAccount
        fields = [
            "delivery_method",
            "autofile_spam",
            "spam_delivery_folder",
            "spam_score_threshold",
            "alias_for",
            "forward_to",
        ]

    ####################################################################
    #
    def __init__(self, *args, **kwargs):
        """
        Make the EmailAccountForm crispy.
        """
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        if self.instance:
            # The `alias_for` and `aliases` field can only list EmailAccount's
            # that have the same owner as the EmailAccount self.instance refers
            # to. Also you can not alias to yourself, so exclude this instance
            # from the queryset of possible valid instances.
            #
            self.fields["aliases"].queryset = EmailAccount.objects.filter(
                owner=self.instance.owner
            ).exclude(pk=self.instance.pk)
            self.fields["alias_for"].queryset = EmailAccount.objects.filter(
                owner=self.instance.owner
            ).exclude(pk=self.instance.pk)

            # and give each form entry a unique html/css id with a known
            # pattern that our vue code can use to find this form on the page.
            #
            self.helper.form_id = f"email-account-form-{self.instance.pk}"
        else:
            self.helper.form_id = "new-email-account-form-id"

        # self.helper.form_class = "blueForms"
        self.helper.form_method = "post"
        self.helper.form_action = "as_email:email-account-detail"

        self.helper.add_input(Submit("submit", "Submit"))
