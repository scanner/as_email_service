#!/usr/bin/env python
#
"""Tests for the autoconfig (Mozilla) and autodiscover (Microsoft) views."""

# system imports
#
from collections.abc import Callable

# 3rd party imports
#
import pytest
from django.test import Client
from django.urls import reverse

# Project imports
#
from as_email.models import Server
from as_email.views import AUTODISCOVER_REQUEST_NS

pytestmark = pytest.mark.django_db


####################################################################
#
def autodiscover_request_body(email_address: str) -> bytes:
    """Build a minimal Outlook Autodiscover request body for `email_address`."""
    return (
        f'<Autodiscover xmlns="{AUTODISCOVER_REQUEST_NS}">'
        "<Request>"
        f"<EMailAddress>{email_address}</EMailAddress>"
        "</Request>"
        "</Autodiscover>"
    ).encode()


########################################################################
########################################################################
#
class TestAutoconfigView:
    """Tests for the Mozilla autoconfig GET endpoint."""

    ####################################################################
    #
    @pytest.mark.parametrize(
        "url_name",
        ["autoconfig", "autoconfig_well_known"],
        ids=["default-path", "well-known-path"],
    )
    def test_valid_domain_renders_full_config(
        self,
        client: Client,
        server_factory: Callable[..., Server],
        settings,
        url_name: str,
    ) -> None:
        """
        GIVEN: a Server with a send_provider, IMAP configured instance-wide,
               and no mail_hostname override
        WHEN:  either the default or well-known autoconfig URL is requested
               with a valid emailaddress
        THEN:  a 200 XML response is returned with SMTP and IMAP sections
               both pointing at settings.SITE_NAME
        """
        settings.IMAP_HOSTNAME = "imap.example.com"
        server = server_factory(domain_name="example.com")

        resp = client.get(
            reverse(url_name),
            {"emailaddress": f"alice@{server.domain_name}"},
        )

        assert resp.status_code == 200
        assert resp["Content-Type"] == "application/xml"
        content = resp.content.decode()
        assert "<domain>example.com</domain>" in content
        assert f"<hostname>{settings.SITE_NAME}</hostname>" in content
        assert "<hostname>imap.example.com</hostname>" in content
        assert f"<port>{settings.SMTP_SUBMISSION_PORT}</port>" in content
        assert f"<port>{settings.IMAP_PORT}</port>" in content

    ####################################################################
    #
    @pytest.mark.parametrize(
        "query_params,expected_status",
        [
            ({}, 400),
            ({"emailaddress": ""}, 400),
            ({"emailaddress": "not-an-email-address"}, 400),
            (
                {"emailaddress": "alice@no-such-domain.example.net"},
                404,
            ),
        ],
        ids=[
            "missing-param",
            "empty-param",
            "no-at-sign",
            "unknown-domain",
        ],
    )
    def test_error_responses(
        self,
        client: Client,
        query_params: dict,
        expected_status: int,
    ) -> None:
        """
        GIVEN: a GET request with no usable emailaddress, or one whose
               domain has no matching Server
        WHEN:  the autoconfig endpoint is queried
        THEN:  400 is returned before any Server lookup is attempted, or 404
               once a well-formed but unknown domain is looked up
        """
        resp = client.get(reverse("autoconfig"), query_params)
        assert resp.status_code == expected_status

    ####################################################################
    #
    @pytest.mark.parametrize(
        "has_send_provider,imap_hostname_setting,expect_smtp,expect_imap",
        [
            (True, "imap.example.com", True, True),
            (False, "imap.example.com", False, True),
            (True, "", True, False),
        ],
        ids=[
            "smtp-and-imap",
            "no-send-provider-omits-smtp",
            "no-imap-hostname-omits-imap",
        ],
    )
    def test_section_inclusion_depends_on_provider_and_settings(
        self,
        client: Client,
        server_factory: Callable[..., Server],
        settings,
        has_send_provider: bool,
        imap_hostname_setting: str,
        expect_smtp: bool,
        expect_imap: bool,
    ) -> None:
        """
        GIVEN: a Server with or without a send_provider, and IMAP_HOSTNAME
               set or blank
        WHEN:  the autoconfig endpoint is queried
        THEN:  the SMTP section appears only when send_provider is set, and
               the IMAP section appears only when IMAP_HOSTNAME is set
        """
        settings.IMAP_HOSTNAME = imap_hostname_setting
        server = server_factory(domain_name="example.com")
        if not has_send_provider:
            server.send_provider = None
            server.save()

        resp = client.get(
            reverse("autoconfig"),
            {"emailaddress": f"alice@{server.domain_name}"},
        )

        assert resp.status_code == 200
        content = resp.content.decode()
        assert ('type="smtp"' in content) is expect_smtp
        assert ('type="imap"' in content) is expect_imap

    ####################################################################
    #
    def test_mail_hostname_override_used_for_both_protocols(
        self,
        client: Client,
        server_factory: Callable[..., Server],
        settings,
    ) -> None:
        """
        GIVEN: a Server with a mail_hostname override set
        WHEN:  the autoconfig endpoint is queried
        THEN:  both the SMTP and IMAP sections use the override, not
               settings.SITE_NAME/IMAP_HOSTNAME
        """
        settings.IMAP_HOSTNAME = "imap.example.com"
        server = server_factory(
            domain_name="example.com",
            mail_hostname="mail2.example.com",
        )

        resp = client.get(
            reverse("autoconfig"),
            {"emailaddress": f"alice@{server.domain_name}"},
        )

        content = resp.content.decode()
        assert content.count("<hostname>mail2.example.com</hostname>") == 2
        assert settings.SITE_NAME not in content
        assert "imap.example.com" not in content


########################################################################
########################################################################
#
class TestAutodiscoverView:
    """Tests for the Microsoft autodiscover POST endpoint."""

    ####################################################################
    #
    def test_valid_post_renders_full_config(
        self,
        client: Client,
        server_factory: Callable[..., Server],
        settings,
    ) -> None:
        """
        GIVEN: a Server with a send_provider and IMAP configured
        WHEN:  a valid Autodiscover request POSTs the account's email address
        THEN:  a 200 XML response is returned with both Protocol blocks,
               pointing at settings.SITE_NAME, and the LoginName echoed back
        """
        settings.IMAP_HOSTNAME = "imap.example.com"
        server = server_factory(domain_name="example.com")
        email_address = f"alice@{server.domain_name}"

        resp = client.post(
            reverse("autodiscover"),
            data=autodiscover_request_body(email_address),
            content_type="application/xml",
        )

        assert resp.status_code == 200
        assert resp["Content-Type"] == "application/xml"
        content = resp.content.decode()
        assert "<Type>IMAP</Type>" in content
        assert "<Type>SMTP</Type>" in content
        assert f"<Server>{settings.SITE_NAME}</Server>" in content
        assert "<Server>imap.example.com</Server>" in content
        assert content.count(f"<LoginName>{email_address}</LoginName>") == 2

    ####################################################################
    #
    @pytest.mark.parametrize(
        "body,expected_status",
        [
            (b"not xml at all", 400),
            (b"", 400),
            (
                f'<Autodiscover xmlns="{AUTODISCOVER_REQUEST_NS}">'
                "<Request></Request></Autodiscover>".encode(),
                400,
            ),
            (
                autodiscover_request_body("alice@no-such-domain.example.net"),
                404,
            ),
        ],
        ids=[
            "malformed-xml",
            "empty-body",
            "missing-emailaddress-element",
            "unknown-domain",
        ],
    )
    def test_error_responses(
        self, client: Client, body: bytes, expected_status: int
    ) -> None:
        """
        GIVEN: a POST body that is not parseable XML, is missing/blank the
               EMailAddress element, or names a domain with no matching
               Server
        WHEN:  the autodiscover endpoint is queried
        THEN:  400 is returned before any Server lookup is attempted, or 404
               once a well-formed but unknown domain is looked up
        """
        resp = client.post(
            reverse("autodiscover"),
            data=body,
            content_type="application/xml",
        )
        assert resp.status_code == expected_status

    ####################################################################
    #
    @pytest.mark.parametrize(
        "has_send_provider,imap_hostname_setting,expect_smtp,expect_imap",
        [
            (True, "imap.example.com", True, True),
            (False, "imap.example.com", False, True),
            (True, "", True, False),
        ],
        ids=[
            "smtp-and-imap",
            "no-send-provider-omits-smtp",
            "no-imap-hostname-omits-imap",
        ],
    )
    def test_section_inclusion_depends_on_provider_and_settings(
        self,
        client: Client,
        server_factory: Callable[..., Server],
        settings,
        has_send_provider: bool,
        imap_hostname_setting: str,
        expect_smtp: bool,
        expect_imap: bool,
    ) -> None:
        """
        GIVEN: a Server with or without a send_provider, and IMAP_HOSTNAME
               set or blank
        WHEN:  the autodiscover endpoint is queried
        THEN:  the SMTP Protocol block appears only when send_provider is
               set, and the IMAP block appears only when IMAP_HOSTNAME is set
        """
        settings.IMAP_HOSTNAME = imap_hostname_setting
        server = server_factory(domain_name="example.com")
        if not has_send_provider:
            server.send_provider = None
            server.save()

        resp = client.post(
            reverse("autodiscover"),
            data=autodiscover_request_body(f"alice@{server.domain_name}"),
            content_type="application/xml",
        )

        assert resp.status_code == 200
        content = resp.content.decode()
        assert ("<Type>SMTP</Type>" in content) is expect_smtp
        assert ("<Type>IMAP</Type>" in content) is expect_imap

    ####################################################################
    #
    def test_mail_hostname_override_used_for_both_protocols(
        self,
        client: Client,
        server_factory: Callable[..., Server],
        settings,
    ) -> None:
        """
        GIVEN: a Server with a mail_hostname override set
        WHEN:  the autodiscover endpoint is queried
        THEN:  both Protocol blocks use the override, not
               settings.SITE_NAME/IMAP_HOSTNAME
        """
        settings.IMAP_HOSTNAME = "imap.example.com"
        server = server_factory(
            domain_name="example.com",
            mail_hostname="mail2.example.com",
        )

        resp = client.post(
            reverse("autodiscover"),
            data=autodiscover_request_body(f"alice@{server.domain_name}"),
            content_type="application/xml",
        )

        content = resp.content.decode()
        assert content.count("<Server>mail2.example.com</Server>") == 2
        assert settings.SITE_NAME not in content
        assert "imap.example.com" not in content
