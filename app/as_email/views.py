"""
The simplistic set of views for the users of the as_email app.

For adminstrative functions this is supported by the django admin interface.

These views are for users. It needs to provide functions to:
- list their email accounts
- update/set password for their email accounts
- set blocked message policy, delivery folder
- set account type: delivery, alias, forwarding
- for alias let them add and remove aliases (to other email accounts that they
  control.)
- for forwarding - set a forwarding address
- test forwarding address
- examine blocked messages and choose to deliver them
- create mail filter rules for an email account
  - import maildelivery file for creation of mail filter rules
- order mail filter rules (for an email account)

"""
from django.contrib.auth.decorators import login_required
from django.shortcuts import render  # NOQA: F401

# Create your views here.


####################################################################
#
@login_required
async def email_accounts(request):
    """
    returns a simple view of the email accounts that belong to the user
    """
    pass
