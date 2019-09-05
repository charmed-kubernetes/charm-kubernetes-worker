import sys
from unittest.mock import MagicMock

# mock dependencies which we don't care about covering in our tests
ch = MagicMock()
#sys.modules['charmhelpers'] = ch
#sys.modules['charmhelpers.core'] = ch.core
#sys.modules['charmhelpers.core.unitdata'] = ch.core.unitdata
#sys.modules['charmhelpers.core.host'] = ch.core.host
#sys.modules['charmhelpers.contrib.charmsupport'] = ch.contrib.charmsupport
#sys.modules['charmhelpers.cli'] = ch.cli
charms = MagicMock()
#sys.modules['charms'] = charms
sys.modules['charms.layer'] = charms.layer
sys.modules['charms.layer.kubernetes_common'] = charms.layer.kubernetes_common
sys.modules['charms.templating.jinja2'] = MagicMock()
#reactive = MagicMock()
#sys.modules['charms.reactive'] = reactive
#sys.modules['charms.reactive.helpers'] = reactive.helpers
