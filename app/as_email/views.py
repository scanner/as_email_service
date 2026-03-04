"""
The simplistic set of views for the users of the as_email app.

For adminstrative functions this is supported by the django admin interface.

These views are for users. It needs to provide functions to:
- list their email accounts
- update/set password for their email accounts
- manage delivery methods (local delivery, alias delivery)
- create mail filter rules for an email account
  - import maildelivery file for creation of mail filter rules
- order mail filter rules (for an email account)

"""

# System imports
#
import logging

# 3rd party imports
#
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.db.models import Count, Prefetch, Q
from django.http import (
    Http404,
    HttpResponse,
    HttpResponseBadRequest,
)
from django.shortcuts import render
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from drf_spectacular.extensions import OpenApiAuthenticationExtension
from drf_spectacular.utils import (
    PolymorphicProxySerializer,
    extend_schema,
    extend_schema_view,
    inline_serializer,
)
from dry_rest_permissions.generics import (
    DRYPermissionFiltersBase,
    DRYPermissions,
)
from rest_framework import fields as drf_fields, mixins, serializers, status
from rest_framework.authentication import (
    BasicAuthentication,
    SessionAuthentication,
)
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet, ModelViewSet

# Project imports
#
from .models import (
    AliasToDelivery,
    DeliveryMethod,
    EmailAccount,
    ImapDelivery,
    LocalDelivery,
    MessageFilterRule,
    Provider,
    Server,
)
from .serializers import (
    AliasToDeliverySerializer,
    DeliveryMethodSerializer,
    EmailAccountSerializer,
    ImapDeliverySerializer,
    LocalDeliverySerializer,
    MessageFilterRuleSerializer,
    MoveOrderSerializer,
    PasswordSerializer,
    TestImapConnectionSerializer,
)

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
def about(request):
    """Simple about page."""
    return render(request, "as_email/about.html", {})


####################################################################
#
@login_required
def contact(request):
    """Simple contact page with mailto link to the admin address."""
    return render(request, "as_email/contact.html", {})


####################################################################
#
@login_required
def documentation(request):
    """User-facing documentation page."""
    return render(request, "as_email/documentation.html", {})


####################################################################
#
@login_required
def index(request):
    """
    returns a simple view of the email accounts that belong to the user
    """
    user = request.user
    email_accounts = (
        EmailAccount.objects.filter(owner=user)
        .annotate(
            dm_total=Count("delivery_methods"),
            dm_enabled=Count(
                "delivery_methods",
                filter=Q(delivery_methods__enabled=True),
            ),
        )
        .prefetch_related(
            Prefetch(
                "aliased_from",
                queryset=AliasToDelivery.objects.select_related(
                    "email_account"
                ),
            )
        )
    )
    email_accounts_serialized = {
        ea.pk: EmailAccountSerializer(ea, context={"request": request})
        for ea in email_accounts
    }

    # Create a dictionary that gives the field info from the django rest
    # framework for an EmailAccount object so that our UI knows how to
    # represent them and what info to include in the forms (used for tooltips).
    #
    actions = {}
    if email_accounts_serialized:
        serializer = list(email_accounts_serialized.values())[0]
        eavs = EmailAccountViewSet()
        md = eavs.metadata_class()
        actions = {
            field_name: md.get_field_info(field)
            for field_name, field in serializer.fields.items()
            if not isinstance(field, serializers.HiddenField)
        }

    vue_data = {
        "email_accounts_data": {
            f"pk{ea.pk}": {
                **dict(email_accounts_serialized[ea.pk].data),
                "delivery_methods_url": reverse(
                    "as_email:delivery-method-list",
                    kwargs={"email_account_pk": ea.pk},
                ),
                "dm_total": ea.dm_total,
                "dm_enabled": ea.dm_enabled,
                "aliased_from": [
                    {
                        "email": atd.email_account.email_address,
                        "enabled": atd.enabled,
                    }
                    for atd in ea.aliased_from.all()
                ],
            }
            for ea in email_accounts
        },
        "num_email_accounts": len(email_accounts_serialized),
        "valid_email_addresses": [x.email_address for x in email_accounts],
        "email_account_field_info": actions,
    }
    context = {
        "email_accounts": list(email_accounts),
        "vue_data": vue_data,
    }
    return render(request, "as_email/index.html", context)


####################################################################
#
def _get_provider_for_webhook(server: Server, provider_name: str) -> Provider:
    """
    Get the provider backend for handling webhooks for the given server.

    Args:
        server: The Server instance
        provider_name: The provider name from the URL (e.g., "postmark")

    Returns:
        The provider instance that matches the provider_name

    Raises:
        Http404: If the provider is not configured for this server
    """
    # Check if this provider is in the server's receive_providers
    #
    provider = server.receive_providers.filter(
        backend_name=provider_name
    ).first()
    if not provider:
        raise Http404(
            f"Provider '{provider_name}' is not configured as a receive "
            f"provider for server '{server.domain_name}'"
        )
    return provider


####################################################################
#
@csrf_exempt
@require_POST
def hook_incoming(request, provider_name: str, domain_name: str):
    """
    Generic incoming email webhook handler.

    Routes the webhook to the appropriate provider backend based on the
    provider_name in the URL. The provider backend handles all
    provider-specific logic.

    Args:
        request: The HTTP request containing the webhook payload
        provider_name: The provider name from the URL (e.g., "postmark")
        domain_name: The domain name of the server

    Returns:
        JsonResponse or HttpResponseBadRequest
    """
    server = _validate_server_api_key(request, domain_name)
    provider = _get_provider_for_webhook(server, provider_name)

    # Check if the provider backend supports this webhook
    #
    if not hasattr(provider.backend, "handle_incoming_webhook"):
        logger.error(
            "Provider '%s' does not support incoming webhook",
            provider_name,
        )
        return HttpResponseBadRequest(
            f"Provider '{provider_name}' does not support incoming webhooks"
        )

    return provider.backend.handle_incoming_webhook(request, server)


####################################################################
#
@csrf_exempt
@require_POST
def hook_bounce(request, provider_name: str, domain_name: str):
    """
    Generic bounce notification webhook handler.

    Routes the webhook to the appropriate provider backend based on the
    provider_name in the URL. The provider backend handles all
    provider-specific logic.

    Args:
        request: The HTTP request containing the webhook payload
        provider_name: The provider name from the URL (e.g., "postmark")
        domain_name: The domain name of the server

    Returns:
        JsonResponse or HttpResponseBadRequest
    """
    server = _validate_server_api_key(request, domain_name)
    provider = _get_provider_for_webhook(server, provider_name)

    # Check if the provider backend supports this webhook
    #
    if not hasattr(provider.backend, "handle_bounce_webhook"):
        logger.error(
            "Provider '%s' does not support bounce webhook",
            provider_name,
        )
        return HttpResponseBadRequest(
            f"Provider '{provider_name}' does not support bounce webhooks"
        )

    return provider.backend.handle_bounce_webhook(request, server)


####################################################################
#
@csrf_exempt
@require_POST
def hook_spam(request, provider_name: str, domain_name: str):
    """
    Generic spam complaint webhook handler.

    Routes the webhook to the appropriate provider backend based on the
    provider_name in the URL. The provider backend handles all
    provider-specific logic.

    Args:
        request: The HTTP request containing the webhook payload
        provider_name: The provider name from the URL (e.g., "postmark")
        domain_name: The domain name of the server

    Returns:
        JsonResponse or HttpResponseBadRequest
    """
    server = _validate_server_api_key(request, domain_name)
    provider = _get_provider_for_webhook(server, provider_name)

    # Check if the provider backend supports this webhook
    #
    if not hasattr(provider.backend, "handle_spam_webhook"):
        logger.error(
            "Provider '%s' does not support spam webhook",
            provider_name,
        )
        return HttpResponseBadRequest(
            f"Provider '{provider_name}' does not support spam webhooks"
        )

    return provider.backend.handle_spam_webhook(request, server)


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


class CSRFExemptSessionScheme(OpenApiAuthenticationExtension):
    """Tell drf-spectacular that CSRFExemptSessionAuthentication is
    just session auth (cookie-based)."""

    target_class = "as_email.views.CSRFExemptSessionAuthentication"
    name = "sessionAuth"

    def get_security_definition(self, auto_schema):
        return {"type": "apiKey", "in": "cookie", "name": "sessionid"}


########################################################################
########################################################################
#
class OwnerFilterBackend(DRYPermissionFiltersBase):
    def filter_list_queryset(self, request, queryset, view):
        """
        Limits all list requests to only be seen by the owners.
        """
        # Owner or admin or super user can see.
        #
        # if request.user.is_admin or request.user.is_superuser:
        #     return queryset

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
    @extend_schema(
        request=PasswordSerializer,
        responses={
            200: inline_serializer(
                "SetPasswordResponse",
                fields={"status": drf_fields.CharField()},
            )
        },
    )
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
    def get_queryset(self):
        return MessageFilterRule.objects.filter(
            email_account=self.kwargs["email_account_pk"]
        )

    ####################################################################
    #
    def get_serializer_class(self):
        if self.action == "move":
            return MoveOrderSerializer
        return MessageFilterRuleSerializer

    ####################################################################
    #
    @extend_schema(
        request=MoveOrderSerializer,
        responses={
            200: inline_serializer(
                "MoveResponse",
                fields={
                    "status": drf_fields.CharField(),
                    "url": drf_fields.URLField(),
                    "order": drf_fields.IntegerField(),
                },
            )
        },
    )
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


########################################################################
########################################################################
#
# Map the delivery_type request field to the concrete model and serializer.
#
_DELIVERY_TYPE_MAP: dict[
    str, tuple[type[DeliveryMethod], type[DeliveryMethodSerializer]]
] = {
    "LocalDelivery": (LocalDelivery, LocalDeliverySerializer),
    "AliasToDelivery": (AliasToDelivery, AliasToDeliverySerializer),
    "ImapDelivery": (ImapDelivery, ImapDeliverySerializer),
}


########################################################################
########################################################################
#
class DeliveryMethodOwnerFilterBackend(DRYPermissionFiltersBase):
    def filter_list_queryset(self, request, queryset, view):
        """
        Limits list requests to delivery methods belonging to the requesting
        user's email accounts.
        """
        return queryset.filter(email_account__owner=request.user)


########################################################################
########################################################################
#
_delivery_method_polymorphic = PolymorphicProxySerializer(
    component_name="DeliveryMethodPolymorphic",
    serializers=[
        LocalDeliverySerializer,
        AliasToDeliverySerializer,
        ImapDeliverySerializer,
    ],
    resource_type_field_name="delivery_type",
)


@extend_schema_view(
    list=extend_schema(
        responses=_delivery_method_polymorphic,
        description="List all delivery methods for the email account.",
    ),
    retrieve=extend_schema(
        responses=_delivery_method_polymorphic,
        description="Retrieve a specific delivery method.",
    ),
    create=extend_schema(
        request=_delivery_method_polymorphic,
        responses=_delivery_method_polymorphic,
        description=(
            "Create a new delivery method. Include `delivery_type` "
            '("LocalDelivery", "AliasToDelivery", or "ImapDelivery") to select the subtype.'
        ),
    ),
    update=extend_schema(
        request=_delivery_method_polymorphic,
        responses=_delivery_method_polymorphic,
    ),
    partial_update=extend_schema(
        request=_delivery_method_polymorphic,
        responses=_delivery_method_polymorphic,
    ),
)
class DeliveryMethodViewSet(ModelViewSet):
    """
    CRUD + ordering for DeliveryMethod objects nested under an EmailAccount.

    Supports LocalDelivery, AliasToDelivery, and ImapDelivery subtypes. The
    request body must include a `delivery_type` field (e.g. "LocalDelivery")
    to select the correct subtype serializer on create/update.
    """

    permission_classes = (IsAuthenticated, DRYPermissions)
    serializer_class = DeliveryMethodSerializer
    filter_backends = (DeliveryMethodOwnerFilterBackend,)
    queryset = DeliveryMethod.objects.all()
    authentication_classes = (
        CSRFExemptSessionAuthentication,
        BasicAuthentication,
    )

    ####################################################################
    #
    def get_queryset(self):
        return DeliveryMethod.objects.filter(
            email_account=self.kwargs["email_account_pk"]
        )

    ####################################################################
    #
    def get_serializer_class(self):
        """
        Return the correct serializer based on the concrete subtype.

        For instance-based read/write actions, the actual type of the object
        is used. For create, the client supplies `delivery_type` in the
        request body to select the subtype.

        NOTE: We deliberately avoid calling get_object() here because DRY
        REST Permissions invokes get_serializer_class() during both
        has_permission() and has_object_permission(), and get_object()
        itself calls check_object_permissions() → has_object_permission() →
        get_serializer_class(), causing infinite recursion. Instead we look
        up the concrete type directly from the queryset using just the pk.
        """
        # For instance-based actions, determine the concrete subtype from
        # the DB without going through the full get_object() pipeline.
        #
        if self.action in ("retrieve", "update", "partial_update", "destroy"):
            pk = self.kwargs.get("pk")
            if pk:
                try:
                    instance = self.get_queryset().get(pk=pk)
                    entry = _DELIVERY_TYPE_MAP.get(type(instance).__name__)
                    if entry:
                        return entry[1]
                except DeliveryMethod.DoesNotExist:
                    pass

        # For create (and list fallback) use the delivery_type in the request.
        #
        delivery_type = self.request.data.get("delivery_type")
        if delivery_type and delivery_type in _DELIVERY_TYPE_MAP:
            return _DELIVERY_TYPE_MAP[delivery_type][1]

        return DeliveryMethodSerializer

    ####################################################################
    #
    def list(self, request, *args, **kwargs):
        """
        Return each delivery method serialized with its concrete subtype
        serializer so that type-specific fields (autofile_spam,
        target_account, etc.) are included alongside the base fields.

        The default get_serializer_class() returns the base
        DeliveryMethodSerializer for list actions (no pk, no delivery_type
        in the GET request), which omits all subclass fields — causing the
        UI to show wrong values on page load.
        """
        queryset = self.filter_queryset(self.get_queryset())
        ctx = self.get_serializer_context()
        data = []
        for instance in queryset:
            entry = _DELIVERY_TYPE_MAP.get(type(instance).__name__)
            serializer_cls = entry[1] if entry else DeliveryMethodSerializer
            data.append(serializer_cls(instance, context=ctx).data)
        return Response(data)

    ####################################################################
    #
    def create(self, request, *args, **kwargs):
        """
        Create a new DeliveryMethod under the specified EmailAccount.

        The `delivery_type` field selects the concrete subtype
        (LocalDelivery or AliasToDelivery).
        """
        delivery_type = request.data.get("delivery_type")
        if not delivery_type or delivery_type not in _DELIVERY_TYPE_MAP:
            return Response(
                {
                    "delivery_type": (
                        f"Must be one of: {list(_DELIVERY_TYPE_MAP.keys())}"
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Enforce max-one LocalDelivery per account.
        #
        if delivery_type == "LocalDelivery":
            ea_pk = kwargs["email_account_pk"]
            if LocalDelivery.objects.filter(email_account_id=ea_pk).exists():
                return Response(
                    {
                        "delivery_type": (
                            "An account may have at most one LocalDelivery."
                        )
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

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

    ####################################################################
    #
    @extend_schema(
        request=TestImapConnectionSerializer,
        responses={
            200: inline_serializer(
                "TestImapOk",
                fields={
                    "success": drf_fields.BooleanField(),
                    "message": drf_fields.CharField(),
                },
            ),
            400: inline_serializer(
                "TestImapFail",
                fields={
                    "success": drf_fields.BooleanField(),
                    "message": drf_fields.CharField(),
                },
            ),
        },
        description=(
            "Test IMAP connection credentials without saving to the database. "
            "Returns {success, message}."
        ),
    )
    @action(detail=False, methods=["post"], url_path="test_imap")
    def test_imap(self, request, **kwargs):
        """
        Attempt a live IMAP connection with the supplied credentials and report
        the result. Nothing is read from or written to the database.
        """
        serializer = TestImapConnectionSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )
        ok, message = ImapDelivery.test_connection(
            host=serializer.validated_data["imap_host"],
            port=serializer.validated_data["imap_port"],
            username=serializer.validated_data["username"],
            password=serializer.validated_data["password"],
        )
        return Response(
            {"success": ok, "message": message},
            status=status.HTTP_200_OK if ok else status.HTTP_400_BAD_REQUEST,
        )
