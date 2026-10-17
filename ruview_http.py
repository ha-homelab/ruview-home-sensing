"""Compatibility import for the pinned public RuView package.

The implementation is maintained in ha-homelab/ruview-home-assistant.
Install requirements.txt before running this private deployment.
"""

import sys

from ruview_home_assistant import ruview_http as _implementation

sys.modules[__name__] = _implementation
