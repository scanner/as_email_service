#!/usr/bin/env python
#
"""
Tests for the project template tags.
"""

# 3rd party imports
#
import pytest
from django.contrib.auth.models import AnonymousUser, Group, User

# Project imports
#
from project.templatetags.project_tags import (
    is_in_group,
    project_bulma_css,
    project_third_party_js,
)

pytestmark = pytest.mark.django_db


########################################################################
#
class TestIsInGroup:
    """Tests for the is_in_group template filter."""

    ####################################################################
    #
    def test_anonymous_user_not_in_group(self) -> None:
        """
        GIVEN: an anonymous user
        WHEN:  is_in_group is called
        THEN:  it returns False
        """
        assert is_in_group(AnonymousUser(), "some-group") is False

    ####################################################################
    #
    @pytest.mark.parametrize(
        "in_group,expected", [(True, True), (False, False)]
    )
    def test_authenticated_user_group_membership(
        self, in_group: bool, expected: bool
    ) -> None:
        """
        GIVEN: an authenticated user who is or is not a member of a group
        WHEN:  is_in_group is called with that group name
        THEN:  it returns True if the user is in the group, False otherwise
        """
        user = User.objects.create_user(username="testuser", password="pass")
        group = Group.objects.create(name="admins")
        if in_group:
            user.groups.add(group)
        assert is_in_group(user, "admins") is expected


########################################################################
#
class TestProjectThirdPartyJs:
    """Tests for the project_third_party_js template tag."""

    ####################################################################
    #
    @pytest.mark.parametrize(
        "js_files,expected",
        [
            (["vendor.js"], 'type="text/javascript"'),
            ([], ""),
        ],
    )
    def test_project_third_party_js(
        self, mocker, js_files: list[str], expected: str
    ) -> None:
        """
        GIVEN: django-simple-bulma returns a list of JS files (possibly empty)
        WHEN:  project_third_party_js is called
        THEN:  it returns script tags for each file, or an empty string
        """
        mocker.patch(
            "project.templatetags.project_tags.get_js_files",
            return_value=js_files,
        )
        result = project_third_party_js()
        assert expected in result


########################################################################
#
class TestProjectBulmaCss:
    """Tests for the project_bulma_css template tag."""

    ####################################################################
    #
    @pytest.mark.parametrize(
        "theme,mock_themes,expected_css,expected_id",
        [
            ("", [], "bulma.css", "bulma-css"),
            ("mytheme", ["mytheme"], "mytheme_bulma.css", "bulma-css-mytheme"),
        ],
    )
    def test_project_bulma_css(
        self,
        mocker,
        theme: str,
        mock_themes: list[str],
        expected_css: str,
        expected_id: str,
    ) -> None:
        """
        GIVEN: a valid or absent theme name
        WHEN:  project_bulma_css is called
        THEN:  it returns link tags referencing the correct CSS file and id
        """
        mocker.patch("project.templatetags.project_tags.themes", mock_themes)
        result = project_bulma_css(theme=theme)
        assert expected_css in result
        assert f'id="{expected_id}"' in result

    ####################################################################
    #
    def test_invalid_theme_falls_back_to_default(self, mocker, caplog) -> None:
        """
        GIVEN: an unknown theme name
        WHEN:  project_bulma_css is called
        THEN:  it logs a warning and falls back to the default theme
        """
        mocker.patch("project.templatetags.project_tags.themes", ["default"])
        result = project_bulma_css(theme="nonexistent")
        assert "nonexistent" in caplog.text
        assert 'id="bulma-css"' in result
