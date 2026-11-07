"""Shared test setup.

Import the integration from this checkout before Home Assistant's test harness
puts its own testing_config/custom_components package on sys.path.
"""

import custom_components.security_monitor  # noqa: F401
import pytest


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    yield
