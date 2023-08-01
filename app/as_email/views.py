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
# 3rd party imports
#
from asgiref.sync import sync_to_async
from django.contrib import auth
from django.core.exceptions import PermissionDenied
from django.http import Http404, HttpResponse
from django.shortcuts import render  # NOQA: F401
from django.views.decorators.http import require_POST

# Project imports
#
from .models import EmailAccount, Server


####################################################################
#
async def _validate_server_api_key(request, server_name: str) -> Server:
    """
    Given the request and server_name from the URL we will look up the
    server object and verify that there is an `api_key` on the request that
    matches server.api_key.
    """
    try:
        server = await Server.objects.aget(domain_name=server_name)
    except Server.DoesNotExist:
        raise Http404(f"No server found for stream `{server_name}`")

    if "api_key" not in request:
        raise PermissionDenied("no api_key specified in request")
    if request["api_key"] != server.api_key:
        raise PermissionDenied("invalid api_key specified in request")
    return server


####################################################################
#
async def index(request):
    """
    returns a simple view of the email accounts that belong to the user
    """
    user = await sync_to_async(auth.get_user)(request)
    # XXX Normally we would use the `@login_required` decorator, but that does
    #     not work with async views as of django 4.2 (looks like django5 will
    #     support it.)
    #
    if not user.is_authenticated:
        raise PermissionDenied("must be logged in")
    email_accounts = []
    async for email_account in EmailAccount.objects.filter(user=user):
        email_accounts.append(email_account)

    return HttpResponse(
        f"as email index view for {user}, num email accounts: {len(email_accounts)}"
    )


####################################################################
#
@require_POST
async def hook_incoming(request, stream):
    """
    Incoming email being POST'd to us by the provider.
    """
    server = await _validate_server_api_key(request, stream)
    return HttpResponse(f"received email for {server}")


####################################################################
#
@require_POST
async def hook_bounce(request, stream):
    """
    Bounce notification POST'd to us by the provider.
    """
    server = await _validate_server_api_key(request, stream)
    return HttpResponse(f"received bounced for {server}")


####################################################################
#
@require_POST
async def hook_spam(request, stream):
    """
    Spam notificaiton POST'd to us by the provider.
    """
    server = await _validate_server_api_key(request, stream)
    return HttpResponse(f"received spam notification for {server}")
