#!/usr/bin/env python
#
"""
Tests for the as_email Django admin forms and configuration.
"""
# 3rd party imports
#
import pytest

# system imports
#
from django import forms as django_forms

# Project imports
#
from ..admin import ProviderAdminForm
from ..models import Provider
from .factories import ProviderFactory

pytestmark = pytest.mark.django_db


########################################################################
########################################################################
#
class TestProviderAdminFormInit:
    """smtp_server is split into smtp_host / smtp_port initial values."""

    ################################################################
    #
    @pytest.mark.parametrize(
        "smtp_server, expected_host, expected_port",
        [
            ("smtp.example.com:25", "smtp.example.com", "25"),
            ("smtp.example.com:465", "smtp.example.com", "465"),
            ("smtp.example.com:587", "smtp.example.com", "587"),
            ("smtp.example.com:2525", "smtp.example.com", "2525"),
            # bare hostname (no port) falls back to "25"
            ("smtp.example.com", "smtp.example.com", "25"),
        ],
    )
    def test_smtp_server_is_split_into_initials(
        self, smtp_server: str, expected_host: str, expected_port: str
    ) -> None:
        """
        GIVEN: An existing Provider with smtp_server set
        WHEN:  The ProviderAdminForm is instantiated with that instance
        THEN:  smtp_host and smtp_port initial values are populated correctly
        """
        provider = ProviderFactory(smtp_server=smtp_server)
        form = ProviderAdminForm(instance=provider)
        assert form.initial["smtp_host"] == expected_host
        assert form.initial["smtp_port"] == expected_port

    ################################################################
    #
    def test_no_smtp_initials_when_smtp_server_is_absent(self) -> None:
        """
        GIVEN: A new form (no instance) or an existing provider with blank smtp_server
        WHEN:  The ProviderAdminForm is instantiated
        THEN:  smtp_host and smtp_port are not added to initial
        """
        # New form with no instance
        form = ProviderAdminForm()
        assert "smtp_host" not in form.initial
        assert "smtp_port" not in form.initial

        # Existing receive-only provider with no smtp_server
        provider = ProviderFactory(
            smtp_server="", provider_type=Provider.ProviderType.RECEIVE
        )
        form = ProviderAdminForm(instance=provider)
        assert "smtp_host" not in form.initial
        assert "smtp_port" not in form.initial


########################################################################
########################################################################
#
class TestProviderAdminFormValidation:
    """Form clean() validation: smtp_server assembly, required fields, port range."""

    ################################################################
    #
    @pytest.mark.parametrize(
        "smtp_host, smtp_port, expected_smtp_server",
        [
            ("smtp.example.com", 25, "smtp.example.com:25"),
            ("smtp.example.com", 465, "smtp.example.com:465"),
            ("smtp.example.com", 587, "smtp.example.com:587"),
            ("smtp.example.com", 2525, "smtp.example.com:2525"),
            # blank port falls back to the default of 25
            ("smtp.example.com", "", "smtp.example.com:25"),
        ],
    )
    def test_smtp_server_assembled_from_host_and_port(
        self, smtp_host: str, smtp_port: int | str, expected_smtp_server: str
    ) -> None:
        """
        GIVEN: A send provider form submission with smtp_host and smtp_port
        WHEN:  The form is cleaned
        THEN:  cleaned_data["smtp_server"] is "host:port"
        """
        data = {
            "name": "My Provider",
            "backend_name": "postmark",
            "provider_type": Provider.ProviderType.SEND,
            "smtp_host": smtp_host,
            "smtp_port": smtp_port,
        }
        form = ProviderAdminForm(data=data)
        assert form.is_valid(), form.errors
        assert form.cleaned_data["smtp_server"] == expected_smtp_server

    ################################################################
    #
    @pytest.mark.parametrize(
        "provider_type",
        [Provider.ProviderType.SEND, Provider.ProviderType.BOTH],
    )
    def test_smtp_host_required_for_sending_provider_types(
        self, provider_type: str
    ) -> None:
        """
        GIVEN: A SEND or BOTH provider with smtp_host left blank
        WHEN:  The form is cleaned
        THEN:  A validation error is raised on smtp_host
        """
        data = {
            "name": "My Provider",
            "backend_name": "postmark",
            "provider_type": provider_type,
            "smtp_host": "",
            "smtp_port": 25,
        }
        form = ProviderAdminForm(data=data)
        assert not form.is_valid()
        assert "smtp_host" in form.errors

    ################################################################
    #
    def test_receive_only_allows_blank_smtp(self) -> None:
        """
        GIVEN: A receive-only provider with no smtp_host or smtp_port
        WHEN:  The form is cleaned
        THEN:  The form is valid and smtp_server is stored as empty string
        """
        data = {
            "name": "Receive Only",
            "backend_name": "forwardemail",
            "provider_type": Provider.ProviderType.RECEIVE,
            "smtp_host": "",
            "smtp_port": "",
        }
        form = ProviderAdminForm(data=data)
        assert form.is_valid(), form.errors
        assert form.cleaned_data["smtp_server"] == ""

    ################################################################
    #
    @pytest.mark.parametrize("bad_port", [0, 65536])
    def test_port_out_of_range_is_rejected(self, bad_port: int) -> None:
        """
        GIVEN: A port number outside the valid 1–65535 range
        WHEN:  The form is cleaned
        THEN:  A validation error is raised on smtp_port
        """
        data = {
            "name": "My Provider",
            "backend_name": "postmark",
            "provider_type": Provider.ProviderType.SEND,
            "smtp_host": "smtp.example.com",
            "smtp_port": bad_port,
        }
        form = ProviderAdminForm(data=data)
        assert not form.is_valid()
        assert "smtp_port" in form.errors


########################################################################
########################################################################
#
class TestProviderAdminFormSave:
    """ProviderAdminForm.save() correctly writes smtp_server to the database."""

    ################################################################
    #
    def test_save_persists_smtp_server(self) -> None:
        """
        GIVEN: A valid new provider form submission
        WHEN:  The form is saved
        THEN:  The Provider is in the database with the correct smtp_server
        """
        data = {
            "name": "Save Test",
            "backend_name": "postmark",
            "provider_type": Provider.ProviderType.BOTH,
            "smtp_host": "smtp.postmarkapp.com",
            "smtp_port": 465,
        }
        form = ProviderAdminForm(data=data)
        assert form.is_valid(), form.errors
        provider = form.save()
        assert (
            Provider.objects.get(pk=provider.pk).smtp_server
            == "smtp.postmarkapp.com:465"
        )

    ################################################################
    #
    def test_save_updates_existing_provider(self) -> None:
        """
        GIVEN: An existing Provider
        WHEN:  A form with new smtp_host and smtp_port is saved against it
        THEN:  The stored smtp_server reflects the new values
        """
        provider = ProviderFactory(
            smtp_server="old.host:25", provider_type=Provider.ProviderType.BOTH
        )
        data = {
            "name": provider.name,
            "backend_name": "postmark",
            "provider_type": Provider.ProviderType.BOTH,
            "smtp_host": "new.host.com",
            "smtp_port": 587,
        }
        form = ProviderAdminForm(data=data, instance=provider)
        assert form.is_valid(), form.errors
        form.save()
        assert (
            Provider.objects.get(pk=provider.pk).smtp_server
            == "new.host.com:587"
        )


########################################################################
########################################################################
#
class TestProviderAdminFormBackendChoices:
    """backend_name is a dropdown restricted to registered providers."""

    ################################################################
    #
    def test_backend_name_is_a_choice_field_with_registered_providers(
        self,
    ) -> None:
        """
        GIVEN: A ProviderAdminForm
        WHEN:  The backend_name field is inspected
        THEN:  It is a ChoiceField containing the registered provider names
        """
        form = ProviderAdminForm()
        field = form.fields["backend_name"]
        assert isinstance(field, django_forms.ChoiceField)
        choice_values = [value for value, _ in field.choices]
        assert "postmark" in choice_values
        assert "forwardemail" in choice_values

    ################################################################
    #
    def test_unregistered_backend_name_is_rejected(self) -> None:
        """
        GIVEN: A form submission with an unregistered backend_name
        WHEN:  The form is cleaned
        THEN:  A validation error is raised on backend_name
        """
        data = {
            "name": "Bad Backend",
            "backend_name": "nonexistent_backend",
            "provider_type": Provider.ProviderType.RECEIVE,
            "smtp_host": "",
            "smtp_port": "",
        }
        form = ProviderAdminForm(data=data)
        assert not form.is_valid()
        assert "backend_name" in form.errors
