# Copyright 2023 Canonical
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import unittest

import ops
import ops.testing
from charm import KubernetesWorkerCharm


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.harness = ops.testing.Harness(KubernetesWorkerCharm)
        self.addCleanup(self.harness.cleanup)

    def test_start(self):
        # Simulate the charm starting
        self.harness.begin_with_initial_hooks()

        # Ensure we set an ActiveStatus with no message
        self.assertEqual(self.harness.model.unit.status, ops.ActiveStatus())
