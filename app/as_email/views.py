""""
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
import logging
from collections import defaultdict

# 3rd party imports
#
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.http import (
    Http404,
    HttpResponse,
    HttpResponseBadRequest,
    JsonResponse,
    QueryDict,
)
from django.shortcuts import render
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from dry_rest_permissions.generics import (
    DRYPermissionFiltersBase,
    DRYPermissions,
)
from rest_framework import mixins, serializers, status
from rest_framework.authentication import (
    BasicAuthentication,
    SessionAuthentication,
)
from rest_framework.decorators import action
from rest_framework.exceptions import ErrorDetail
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet, ModelViewSet

from .forms import EmailAccountForm

# Project imports
#
from .models import EmailAccount, MessageFilterRule, Server
from .serializers import (
    EmailAccountSerializer,
    MessageFilterRuleSerializer,
    MoveOrderSerializer,
    PasswordSerializer,
)
from .tasks import (
    dispatch_incoming_email,
    process_email_bounce,
    process_email_spam,
)
from .utils import split_email_mailbox_hash, write_spooled_email

logger = logging.getLogger("as_email.views")


####################################################################
#
def _validate_server_api_key(request, domain_name: str) -> Server:
    """
    Given the request and domain_name from the URL we will look up the
    server object and verify that there is an `api_key` on the request that
    matches server.api_key.
    """
    try:
        server = Server.objects.get(domain_name=domain_name)
    except Server.DoesNotExist:
        raise Http404(f"No server found for domain_name `{domain_name}`")

    if "api_key" not in request.GET:
        raise PermissionDenied("no api_key specified in request")
    if request.GET["api_key"].strip() != server.api_key:
        raise PermissionDenied("invalid api_key specified in request")
    return server


####################################################################
#
@login_required
def index(request):
    """
    returns a simple view of the email accounts that belong to the user
    """
    user = request.user
    email_accounts = EmailAccount.objects.filter(owner=user)
    email_accounts_data = {
        ea.pk: EmailAccountSerializer(ea, context={"request": request})
        for ea in email_accounts
    }
    email_accounts_w_forms = [
        (ea, EmailAccountForm(instance=ea)) for ea in email_accounts
    ]

    # Create a dicdtionary that gives the field info from the django rest
    # framework for an EmailAccount object so that our UI knows how to
    # represent them and what info to include in the forms.
    #
    actions = {}
    if email_accounts_data:
        serializer = list(email_accounts_data.values())[0]
        eavs = EmailAccountViewSet()
        md = eavs.metadata_class()
        actions = {
            field_name: md.get_field_info(field)
            for field_name, field in serializer.fields.items()
            if not isinstance(field, serializers.HiddenField)
        }

    vue_data = {
        "email_account_list_url": reverse("as_email:email-account-list"),
        "email_accounts_data": {
            f"pk{k}": v.data for k, v in email_accounts_data.items()
        },
        "num_email_accounts": len(email_accounts_data),
        "valid_email_addresses": [x.email_address for x in email_accounts],
        "email_account_field_info": actions,
        "myTitle": "Hello Vue!",
    }
    context = {
        "email_accounts": email_accounts_w_forms,
        "vue_data": vue_data,
    }
    return render(request, "as_email/index.html", context)


####################################################################
#
@csrf_exempt
@require_POST
def hook_postmark_incoming(request, domain_name):
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
    server = _validate_server_api_key(request, domain_name)
    try:
        email = json.loads(request.body)
    except json.JSONDecodeError as exc:
        logger.warning("Incoming web hook for %s: %s", server.domain_name, exc)
        return HttpResponseBadRequest(f"invalid json: {exc}")

    message_id = email["MessageID"] if "MessageID" in email else None
    from_addr = email["From"] if "From" in email else "<unknown>"

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
    addr, _ = split_email_mailbox_hash(email["OriginalRecipient"])
    try:
        email_account = EmailAccount.objects.get(email_address=addr)
    except EmailAccount.DoesNotExist:
        logger.info(
            "Received email for EmailAccount that does not exist: %s, from: %s",
            addr,
            from_addr,
        )
        # XXX here we would log metrics for getting email that no one is going
        #     to receive.
        #
        return JsonResponse(
            {
                "status": "all good",
                "message": f"no such email account '{addr}'",
            },
        )

    spooled_msg_path = write_spooled_email(
        email["OriginalRecipient"],
        server.incoming_spool_dir,
        email["RawEmail"],
        msg_id=message_id,
        msg_date=email["Date"],
    )

    # Fire off async huey task to dispatch the email we just wrote to the spool
    # directory.
    #
    dispatch_incoming_email(email_account.pk, str(spooled_msg_path))
    return JsonResponse(
        {"status": "all good", "message": str(spooled_msg_path)}
    )


####################################################################
#
@csrf_exempt
@require_POST
def hook_postmark_bounce(request, domain_name):
    """
    Bounce notification POST'd to us by postmark. After doing some initial
    validating and formatting the bulk of the work is handled in a huey task.
    """
    server = _validate_server_api_key(request, domain_name)
    try:
        bounce = json.loads(request.body.decode("utf-8"))
    except json.decoder.JSONDecodeError as exc:
        logger.warning(
            f"Bad json from caller: {exc}", extra={"body": request.body}
        )
        return HttpResponseBadRequest(f"invalid json: {exc}")

    # Make sure the json message from postmark contains at least the keys
    # we expect.
    #
    if not all(
        [x in bounce for x in ("From", "Type", "ID", "Email", "Description")]
    ):
        return HttpResponseBadRequest("submitted json missing expected keys")

    logger.info(
        "postmark bounce hook: message from %s to %s: %s",
        bounce["From"],
        bounce["Email"],
        bounce["Description"],
    )

    try:
        ea = EmailAccount.objects.get(email_address=bounce["From"])
    except EmailAccount.DoesNotExist:
        logger.warning(
            "%s from email address that does not belong "
            "to any EmailAccount: %s, server: %s, bounce id: %d, to: %s, "
            "description: %s",
            bounce["Type"],
            bounce["From"],
            server,
            bounce["ID"],
            bounce["Email"],
            bounce["Description"],
            extra=bounce,
        )
        # NOTE: This does not return an error. Not their fault unless they are
        #       buggesed, but we should log it. Maybe we just deleted that
        #       EmailAccount. Hmm.. maybe we should send the bounce message
        #       to the django support email address.
        #
        return JsonResponse(
            {
                "status": "all good",
                "message": f"`from` address '{bounce['From']}' is not an "
                f"EmailAccount on server {server.domain_name}. "
                "Bounce message ignored.",
            }
        )

    # We do the rest of the processing in an async huey task (this will involve
    # querying postmark's bounce API, and sending a notification email to the
    # email account in question.)
    #
    process_email_bounce(ea.pk, bounce)

    return JsonResponse(
        {
            "status": "all good",
            "message": f"received bounce for {server}/{ea.email_address}",
        }
    )


####################################################################
#
@csrf_exempt
@require_POST
def hook_postmark_spam(request, domain_name):
    """
    Spam notificaiton POST'd to us by the provider.  NOTE: When postmark
    invokes this hook they are saying the associated email was marked as spam
    by a remote user. When this happens the account that the email was sent to
    is now "inactive" and can not be used to receive more email sent by us.

    This view does some cursory work on the request and then tosses the rest of
    the work to the huey task for dealing with spam.
    """
    server = _validate_server_api_key(request, domain_name)
    try:
        spam = json.loads(request.body.decode("utf-8"))
    except json.decoder.JSONDecodeError as exc:
        logger.warning(
            f"Bad json from caller: {exc}", extra={"body": request.body}
        )
        return HttpResponseBadRequest(f"invalid json: {exc}")
    # Make sure the json message from postmark contains at least the keys
    # we expect.
    #
    if not all(
        [
            x in spam
            for x in (
                "From",
                "Type",
                "TypeCode",
                "Details",
                "Subject",
                "ID",
                "Email",
                "Description",
            )
        ]
    ):
        logger.warning(
            "submitted json missing expected keys, message: %r", spam
        )
        return HttpResponseBadRequest("submitted json missing expected keys")

    # Just to be safe, try to make sure that the TypeCode is an integer.
    #
    try:
        spam["TypeCode"] = int(spam["TypeCode"])
    except ValueError:
        logger.error(
            "From: %s, to %s, ID: %s - TypeCode is not an integer: '%s'",
            spam["From"],
            spam["Email"],
            spam["ID"],
            spam["TypeCode"],
            extra=spam,
        )
        spam["TypeCode"] = 2048  #  Mark it as 'unknown'

    logger.warning(
        "message from %s to %s. Message ID: %s, Postmark ID: %s: %s",
        spam["From"],
        spam["Email"],
        spam["MessageID"],
        spam["ID"],
        spam["Description"],
        extra=spam,
    )

    try:
        ea = EmailAccount.objects.get(email_address=spam["From"])
    except EmailAccount.DoesNotExist:
        logger.warning(
            "%s from email address that does not belong "
            "to any EmailAccount: %s, server: %s, Postmark id: %d, to: %s, "
            "description: %s",
            spam["Type"],
            spam["From"],
            server,
            spam["ID"],
            spam["Email"],
            spam["Description"],
            extra=spam,
        )
        # NOTE: This does not return an error. Not their fault unless they are
        #       buggesed, but we should log it. Maybe we just deleted that
        #       EmailAccount. Hmm.. maybe we should send the spam message
        #       to the django support email address.
        #
        return JsonResponse(
            {
                "status": "all good",
                "message": f"`from` address '{spam['From']}' is not an "
                f"EmailAccount on server {server.domain_name}. "
                "Spam message ignored.",
            }
        )

    # We do the rest of the processing in an async huey task (this will involve
    # querying postmark's spam API, and sending a notification email to the
    # email account in question.)
    #
    process_email_spam(ea.pk, spam)

    return JsonResponse(
        {
            "status": "all good",
            "message": f"received spam for {server.domain_name}/{ea.email_address}",
        }
    )


####################################################################
#
@csrf_exempt
def hook_forward_valid(request):
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
class CSRFExemptSessionAuthentication(SessionAuthentication):
    """
    Since DRF needs to support both session and non-session based
    authentication to the same views, it enforces CSRF check for only
    authenticated users. This means that only authenticated requests require
    CSRF tokens and anonymous requests may be sent without CSRF tokens.

    We are using an AJAX style API with SessionAuthentication, so we want to
    disable CSRF requirement for unsafe HTTP method. There is no form and I do
    not want to complicate the JavaScript with the need to continually fetch
    CSRF tokens.

    See: https://stackoverflow.com/questions/30871033/django-rest-framework-remove-csrf

    Basically this REST API is meant to be used from JavaScript.

    NOTE: Consider extending the code that submits data via PUT/PATCH/POST to
          fetch a CSRF token right before it submits.
    """

    ####################################################################
    #
    def enforce_csrf(self, request):
        return  # To not perform the csrf check previously happening


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
class EmailAccountViewSet(
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    mixins.ListModelMixin,
    GenericViewSet,
):
    """
    The EmailAccount. This represents an email address active on a server.
    A user may have multiple EmailAccounts.

    NOTE: The EmailAccount can not be created or deleted via the REST API.
    """

    permission_classes = (IsAuthenticated, DRYPermissions)
    serializer_class = EmailAccountSerializer
    queryset = EmailAccount.objects.all()
    filter_backends = (OwnerFilterBackend,)
    authentication_classes = (
        CSRFExemptSessionAuthentication,
        BasicAuthentication,
    )

    ####################################################################
    #
    def get_serializer_class(self):
        if self.action == "set_password":
            return PasswordSerializer
        return EmailAccountSerializer

    ####################################################################
    #
    # XXX We should use python version of zxcvbn to make sure a password
    #     that is too weak is not used.
    #
    @action(detail=True, methods=["post"])
    def set_password(self, request, pk=None):
        ea = self.get_object()
        serializer = PasswordSerializer(data=request.data)
        if serializer.is_valid():
            ea.set_password(serializer.validated_data["password"])
            return Response({"status": "password set"})
        else:
            return Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST,
            )

    ####################################################################
    #
    def update(self, request, *args, **kwargs):
        """
        Since we have the alias_for ManyToManyField with a through
        relationship where the user can only add email accounts to aliases and
        alias_for where the email account owner == instance.owner we have to
        enforce that check here.
        """

        # Make sure all the EmailAccounts aliases and alias_fors listed are
        # ones owned by the same owner as this EmailAccount object.
        #
        # NOTE: if the owner of the EmailAccount instance has the perm
        #       "can_have_foreign_aliases" this this EmailAccount is allowed to
        #       have aliases to EmailAccounts that do not have the same owner.
        #
        instance = self.get_object()
        if not instance.owner.has_perms(["as_email.can_have_foreign_aliases"]):
            bad_fields = defaultdict(list)
            for field in ["alias_for", "aliases"]:
                if field in request.data:
                    if isinstance(request.data, QueryDict):
                        addrs = request.data.getlist(field)
                    else:
                        addrs = request.data[field]
                    eas = EmailAccount.objects.filter(email_address__in=addrs)
                    for ea in eas:
                        if ea.owner != instance.owner:
                            bad_fields[field].append(
                                ErrorDetail(
                                    f"{ea.email_address}: can only alias email "
                                    "accounts owned by the same user: "
                                    f"{instance.owner}",
                                    code="permission_denied",
                                )
                            )
            if bad_fields:
                return Response(bad_fields, status.HTTP_403_FORBIDDEN)

        return super().update(request, *args, **kwargs)


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
class MessageFilterRuleViewSet(ModelViewSet):
    permission_classes = (IsAuthenticated, DRYPermissions)
    serializer_class = MessageFilterRuleSerializer
    filter_backends = (EmailAccountOwnerFilterBackend,)
    queryset = MessageFilterRule.objects.all()
    authentication_classes = (
        CSRFExemptSessionAuthentication,
        BasicAuthentication,
    )

    ####################################################################
    #
    def get_serializer_class(self):
        if self.action == "move":
            return MoveOrderSerializer
        return MessageFilterRuleSerializer

    ####################################################################
    #
    @action(detail=True, methods=["post"])
    def move(self, request, **kwargs):
        """
        Process one of the move commands to change the ordering of message
        filter rules.
        """
        mfr = self.get_object()
        ser = MoveOrderSerializer(data=request.data)
        if not ser.is_valid():
            return Response(ser.errors, status=status.HTTP_400_BAD_REQUEST)

        match ser.validated_data["command"]:
            case MoveOrderSerializer.UP:
                mfr.up()
            case MoveOrderSerializer.DOWN:
                mfr.down()
            case MoveOrderSerializer.TOP:
                mfr.top()
            case MoveOrderSerializer.BOTTOM:
                mfr.bottom()
            case MoveOrderSerializer.TO:
                if "location" not in ser.validated_data:
                    return Response(
                        {"detail": "location required with 'to' command"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                # The ordered object supports arbitrary values for the order,
                # but we want to keep it within the realm of the number of
                # mfr's that exist so the UI can rely upon the order being in
                # that range.
                #
                min_order = MessageFilterRule.objects.get_min_order()
                max_order = MessageFilterRule.objects.get_max_order()
                location = ser.validated_data["location"]
                if location < min_order:
                    location = min_order
                if location > max_order:
                    location = max_order
                mfr.to(location)

        return Response(
            {
                "status": "movied",
                "url": mfr.get_absolute_url(),
                "order": mfr.order,
            }
        )

    ####################################################################
    #
    def create(self, request, *args, **kwargs):
        """
        MessageFilterRule's are nested objects. The view passes in the
        required information about the EmailAccount that this MessageFilterRule
        belongs to. So we need to make sure that this value is set when
        creating.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.validated_data["email_account_id"] = kwargs[
            "email_account_pk"
        ]
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(
            serializer.data, status=status.HTTP_201_CREATED, headers=headers
        )
