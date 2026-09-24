"""Profile services module is intentionally empty in pure core."""

import apps.identity.profile.services as services


def test_profile_services_module_imports() -> None:
    assert services.__doc__
