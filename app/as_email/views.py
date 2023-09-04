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
from aiologger import Logger
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.http import Http404, HttpResponse, JsonResponse
from django.shortcuts import render
from dry_rest_permissions.generics import (
    DRYPermissionFiltersBase,
    DRYPermissions,
)
from rest_framework.viewsets import ModelViewSet

# Project imports
#
from .models import BlockedMessage, EmailAccount, MessageFilterRule, Server
from .serializers import (
    BlockedMessageSerializer,
    EmailAccountSerializer,
    MessageFilterRuleSerializer,
)
from .tasks import dispatch_incoming_email
from .utils import split_email_mailbox_hash, spooled_email

logger = Logger.with_default_handlers(name=__file__)


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
    email_accounts = EmailAccount.objects.filter(owner=user)
    context = {
        "email_accounts": email_accounts,
    }
    return render(request, "as_email/index.html", context)


####################################################################
#
async def hook_postmark_incoming(request, domain_name):
    """
    Incoming email being POST'd to us by a postmark provider.

    When emails come in, postmark will POST to this webhook once for each
    address that it is delivering email for.

    So if a message was "to" "cc" and "bcc" the same address one POST will be
    made to this hook.

    If a message was to two different addresses, but each is served by
    postmark, two POST's to this hook will be made.

    In all cases the key `OriginalRecipient` will contain the email address a
    specific POST is being made for.
    """
    # XXX usually we would have used @require_POST decorator.. but async.
    #     maybe in django 5.0
    #
    if request.method != "POST":
        raise PermissionDenied("must be POST")

    server = await _validate_server_api_key(request, domain_name)
    email = json.loads(request.body)
    message_id = email["MessageID"] if "MessageID" in email else None

    if "OriginalRecipient" not in email:
        logger.warning(
            "email received from postmark without `OriginalRecipient`, "
            "message id: %s",
            message_id,
        )
        return JsonResponse(
            {
                "status": "all good",
                "message": "no original recipient",
            }
        )

    # Find out who this email is being sent to, and validate that there is an
    # EmailAccount for that address. If it is not one we serve, we need to
    # log/record metrics about that but otherwise drop it on the floor.
    #
    # This is wasteful but not wasteful.. we look up all the EmailAccounts that
    # this email will be delivered to, and if it is zero we just stop right
    # here. Wasteful in that we do this lookup again inside the huey task.. but
    # that is probably still better than all the work to write the email to the
    # spool dir and invoke the huey task only for it to do nothing.
    #
    addr = split_email_mailbox_hash(email["OriginalRecipient"])
    try:
        email_account = await EmailAccount.objects.aget(email_address=addr)
    except EmailAccount.DoesNotExist:
        logger.info(
            "Received email for email account that does not exist: %s", addr
        )
        # XXX here we would log metrics for getting email that no one is going
        #     to receive.
        #
        return JsonResponse({"status": "all good"})

    now = datetime.now().isoformat()
    email_file_name = f"{now}-{message_id}.json"
    fname = Path(server.incoming_spool_dir) / email_file_name

    # To account for other mail providers in the future and to reduce the json
    # dict we write to just what we need to deliver the email we create a new
    # dict that will hold what we write in the incoming spool directory.
    #
    email_json = json.dumps(
        spooled_email(
            email["OriginalRecipient"],
            message_id,
            email["Date"],
            email["RawEmail"],
        )
    )

    # We need to make sure that the file is written before we send our
    # response back to Postmark.. but we should not block other async
    # processing while waiting for the file to be written.
    #
    async with aiofiles.open(fname, "w") as f:
        await f.write(email_json)

    # Fire off async huey task to dispatch the email we just wrote to the spool
    # directory.
    #
    dispatch_incoming_email(email_account.pk, fname)
    return JsonResponse({"status": "all good", "message": fname})


####################################################################
#
async def hook_postmark_bounce(request, domain_name):
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
async def hook_postmark_spam(request, domain_name):
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


####################################################################
#
async def hook_forward_valid(request):
    """
    A return call by a user trying to establish an email forward. A link to
    this is sent when the user attempts to validate that an email address used
    for forwarding is valid.
    """
    # The request should have a 'validation_key' and 'email_account_id' as
    # parameters.
    #

    # This should probably re-direct to a view that shows the email account
    # forwarding is being enabled for, and set a flag in the email account
    # indicating the forwarding is okay.
    #
    return HttpResponse("Ok.. ")


########################################################################
########################################################################
#
class OwnerFilterBackend(DRYPermissionFiltersBase):
    def filter_list_queryset(self, request, queryset, view):
        """
        Limits all list requests to only be seen by the owners.
        """
        return queryset.filter(owner=request.user)


########################################################################
########################################################################
#
class EmailAccountViewSet(ModelViewSet):
    permission_classes = (DRYPermissions,)
    serializer_class = EmailAccountSerializer
    queryset = EmailAccount.objects.all()
    filter_backends = (OwnerFilterBackend,)


########################################################################
########################################################################
#
class EmailAccountOwnerFilterBackend(DRYPermissionFiltersBase):
    def filter_list_queryset(self, request, queryset, view):
        """
        Limits all list requests to only be seen by the owner of the
        associated email account.
        """
        return queryset.filter(email_account__owner=request.user)


########################################################################
########################################################################
#
class BlockedMessageViewSet(ModelViewSet):
    permission_classes = (DRYPermissions,)
    serializer_class = BlockedMessageSerializer
    queryset = BlockedMessage.objects.all()
    filter_backends = (EmailAccountOwnerFilterBackend,)


########################################################################
########################################################################
#
class MessageFilterRuleViewSet(ModelViewSet):
    permission_classes = (DRYPermissions,)
    serializer_class = MessageFilterRuleSerializer
    queryset = MessageFilterRule.objects.all()
    filter_backends = (EmailAccountOwnerFilterBackend,)
