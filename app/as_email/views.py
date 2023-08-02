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
# System imports
#
import json
from datetime import datetime
from pathlib import Path

# 3rd party imports
#
import aiofiles
from asgiref.sync import sync_to_async
from django.contrib import auth
from django.core.exceptions import PermissionDenied
from django.http import Http404, HttpResponse, JsonResponse

# Project imports
#
from .models import EmailAccount, Server
from .tasks import dispatch_incoming_email
from .utils import short_hash_email

# from django.shortcuts import render


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
    # XXX Django 5.0 will add request.auser()
    #
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
async def hook_incoming(request, stream):
    """
    Incoming email being POST'd to us by the provider.
    """
    # XXX usually we would have used @require_POST decorator.. but async.
    #     maybe in django 5.0
    #
    if request.method != "POST":
        raise PermissionDenied("must be POST")

    server = await _validate_server_api_key(request, stream)
    email = json.loads(request.body)

    short_hash = short_hash_email(email)
    now = datetime.now().isoformat()
    email_file_name = f"{now}-{short_hash}.json"
    fname = Path(server.incoming_spool_dir) / email_file_name

    # We need to make sure that the file is written before we send our
    # response back to Postmark.. but we should not block other async
    # processing while waiting for the file to be written.
    #
    async with aiofiles.open(fname, "w") as f:
        await f.write(json.dumps(email))

    # Fire off async huey task to dispatch the email we just wrote to the spool
    # directory.
    #
    _ = dispatch_incoming_email(server.pk, fname, short_hash)
    return JsonResponse({"status": "all good", "message": fname})


####################################################################
#
async def hook_bounce(request, stream):
    """
    Bounce notification POST'd to us by the provider.
    """
    # XXX usually we would have used @require_POST decorator.. but async.
    #     maybe in django 5.0
    #
    if request.method != "POST":
        raise PermissionDenied("must be POST")

    server = await _validate_server_api_key(request, stream)
    return HttpResponse(f"received bounced for {server}")


####################################################################
#
async def hook_spam(request, stream):
    """
    Spam notificaiton POST'd to us by the provider.
    """
    # XXX usually we would have used @require_POST decorator.. but async.
    #     maybe in django 5.0
    #
    if request.method != "POST":
        raise PermissionDenied("must be POST")

    server = await _validate_server_api_key(request, stream)
    return HttpResponse(f"received spam notification for {server}")
