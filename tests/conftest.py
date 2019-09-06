import sys
from unittest.mock import MagicMock

# mock dependencies which we don't care about covering in our tests
ch = MagicMock()
charms = MagicMock()
sys.modules['charms.layer'] = charms.layer
sys.modules['charms.layer.kubernetes_common'] = charms.layer.kubernetes_common
sys.modules['charms.templating.jinja2'] = MagicMock()
