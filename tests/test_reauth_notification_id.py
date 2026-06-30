"""Regression tests for the reauth_notification_id helper.

Round-3 Codex finding (DRY drift class): the persistent-notification id used for
the reauth prompt is now built from a single source so the create site and every
dismiss site cannot drift. A drift would leave the persistent notification
orphaned on unload (create id != dismiss id).
"""

from custom_components.alexa_media.helpers import reauth_notification_id


def test_id_strips_scheme_and_uses_underscore_separator():
    """The id is built from the host (no scheme) with an underscore separator.

    This pins the corrected format and guards against the previous broken
    dismiss-site format ``alexa_media_<email><url[7:]>`` which omitted the
    underscore separator and sliced the scheme off by a fixed offset.
    """
    result = reauth_notification_id("user@example.com", "https://alexa.amazon.com")

    assert result == "alexa_media_user_example_com_alexa_amazon_com"
    # The underscore separator between email slug and host slug must be present;
    # the old broken format concatenated them directly.
    assert "_com_alexa_amazon_com" in result
    # Explicit regression anchor: the previous broken dismiss-site format
    # (no separator, url[7:] slice) must no longer be produced.
    assert result != "alexa_media_user_example_comalexa_amazon_com"


def test_create_and_dismiss_produce_identical_ids():
    """Identical inputs yield byte-identical ids (create/dismiss symmetry)."""
    email = "user@example.com"
    url = "https://alexa.amazon.co.uk"

    assert (
        reauth_notification_id(email, url)
        == "alexa_media_user_example_com_alexa_amazon_co_uk"
    )
    # Symmetry: the create call and the dismiss call use the same construction.
    assert reauth_notification_id(email, url) == reauth_notification_id(email, url)


def test_id_falls_back_to_raw_url_without_scheme():
    """A url without a parsable hostname falls back to the raw url string."""
    # ``amazon.com`` has no scheme, so urlparse().hostname is None and the helper
    # falls back to slugifying the raw url. The old format's ``url[7:]`` slice
    # would have corrupted such a value.
    result = reauth_notification_id("user@example.com", "amazon.com")

    assert result == "alexa_media_user_example_com_amazon_com"
