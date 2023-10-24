"""
Forms for as_email.
"""
# system imports
#

# 3rd party imports
#
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Fieldset, Layout
from django import forms
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

# project imports
#
from .models import EmailAccount


########################################################################
########################################################################
#
class EmailAccountForm(forms.ModelForm):
    aliases = forms.ModelMultipleChoiceField(
        queryset=None,
        help_text=_(
            "This is the reverse part of the `alias_for` relationship. It "
            "lists all the EmailAccounts that are an alias for this "
            "EmailAccount. NOTE: Adding and removing entries from this field "
            "updates `alias_for` on the added or removed EmailAccount."
        ),
        widget=forms.SelectMultiple(
            attrs={
                "data-type": "tags",
                "data-placeholder": "Choose email accounts",
            }
        ),
    )
    alias_for = forms.ModelMultipleChoiceField(
        queryset=None,
        help_text=EmailAccount.alias_for.field.help_text,
        widget=forms.SelectMultiple(
            attrs={
                "data-type": "tags",
                "data-placeholder": "Choose email accounts",
            }
        ),
    )

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
        self.helper = FormHelper(self)
        if self.instance:
            # The `alias_for` and `aliases` field can only list EmailAccount's
            # that have the same owner as the EmailAccount self.instance refers
            # to. Also you can not alias to yourself, so exclude this instance
            # from the queryset of possible valid instances.
            #
            self.fields["aliases"].queryset = EmailAccount.objects.filter(
                owner=self.instance.owner
            ).exclude(pk=self.instance.pk)
            self.fields["aliases"].initial = self.instance.aliases.all()
            self.fields["alias_for"].queryset = EmailAccount.objects.filter(
                owner=self.instance.owner
            ).exclude(pk=self.instance.pk)

            # and give each form entry a unique html/css id with a known
            # pattern that our vue code can use to find this form on the page.
            #
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
        self.helper.layout = Layout(
            Fieldset(
                "",
                "delivery_method",
            ),
            Fieldset(
                "Delivery to Local or IMAP",
                "autofile_spam",
                "spam_delivery_folder",
                "spam_score_threshold",
                css_class="box has-ribbon",
                legend_class="ribbon is-primary",
            ),
            Fieldset(
                "Delivery via Alias",
                "alias_for",
                "aliases",
                css_class="box has-ribbon",
                legend_class="ribbon is-primary",
            ),
            Fieldset(
                "Delivery via Forwarding",
                "forward_to",
                css_class="box has-ribbon",
                legend_class="ribbon is-primary",
            ),
        )
