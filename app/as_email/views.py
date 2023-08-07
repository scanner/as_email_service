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
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.http import Http404, HttpResponse, JsonResponse
from django.shortcuts import render

# Project imports
#
from .models import EmailAccount, Server
from .tasks import dispatch_incoming_email
from .utils import aemail_accounts_by_addr, short_hash_email


####################################################################
#
async def _validate_server_api_key(request, domain_name: str) -> Server:
    """
    Given the request and domain_name from the URL we will look up the
    server object and verify that there is an `api_key` on the request that
    matches server.api_key.
    """
    try:
        server = await Server.objects.aget(domain_name=domain_name)
    except Server.DoesNotExist:
        raise Http404(f"No server found for domain_name `{domain_name}`")

    if "api_key" not in request:
        raise PermissionDenied("no api_key specified in request")
    if request["api_key"] != server.api_key:
        raise PermissionDenied("invalid api_key specified in request")
    return server


####################################################################
#
@login_required
def index(request):
    """
    returns a simple view of the email accounts that belong to the user
    """
    # XXX In Django 5.0 we will see if we can move this to an async view. Too
    #     much just does not work well with async views (like async db lookups
    #     during django template rendering, @login_required)
    user = request.user
    email_accounts = EmailAccount.objects.filter(user=user)
    context = {
        "email_accounts": email_accounts,
    }
    return render(request, "as_email/index.html", context)


####################################################################
#
async def hook_incoming(request, domain_name):
    """
    Incoming email being POST'd to us by the provider.
    """
    # XXX usually we would have used @require_POST decorator.. but async.
    #     maybe in django 5.0
    #
    if request.method != "POST":
        raise PermissionDenied("must be POST")

    server = await _validate_server_api_key(request, domain_name)
    email = json.loads(request.body)

    # This is wasteful but not wasteful.. we look up all the EmailAccounts that
    # this email will be delivered to, and if it is zero we just stop right
    # here. Wasteful in that we do this lookup again inside the huey task.. but
    # that is probably still better than all the work to write the email to the
    # spool dir and invoke the huey task only for it to do nothing.
    #
    email_accounts = await aemail_accounts_by_addr(server, email)
    if not email_accounts:
        # XXX here we would log metrics for getting email that no one is going
        #     to receive.
        #
        return JsonResponse({"status": "all good"})

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
    dispatch_incoming_email(server.pk, fname, short_hash)
    return JsonResponse({"status": "all good", "message": fname})


####################################################################
#
async def hook_bounce(request, domain_name):
    """
    Bounce notification POST'd to us by the provider.
    """
    # XXX usually we would have used @require_POST decorator.. but async.
    #     maybe in django 5.0
    #
    if request.method != "POST":
        raise PermissionDenied("must be POST")

    server = await _validate_server_api_key(request, domain_name)
    return HttpResponse(f"received bounced for {server}")


####################################################################
#
async def hook_spam(request, domain_name):
    """
    Spam notificaiton POST'd to us by the provider.
    """
    # XXX usually we would have used @require_POST decorator.. but async.
    #     maybe in django 5.0
    #
    if request.method != "POST":
        raise PermissionDenied("must be POST")

    server = await _validate_server_api_key(request, domain_name)
    return HttpResponse(f"received spam notification for {server}")
