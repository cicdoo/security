from odoo.tests.common import BaseCase, tagged

from ..models.ir_http import _network_key, _param_enabled


@tagged('post_install', '-at_install')
class TestSessionIpBinding(BaseCase):

    def test_exact(self):
        self.assertEqual(_network_key('10.1.2.3', 'exact'), '10.1.2.3')

    def test_subnet_ipv4(self):
        self.assertEqual(_network_key('10.1.2.3', 'subnet'), '10.1.2.0/24')

    def test_subnet_ipv6(self):
        self.assertEqual(_network_key('2001:db8:1:2:3::5', 'subnet'), '2001:db8:1:2::/64')

    def test_invalid(self):
        self.assertEqual(_network_key('garbage', 'subnet'), 'garbage')

    def test_param(self):
        for v in ('False', 'false', '0', ''):
            self.assertFalse(_param_enabled(v))
        self.assertTrue(_param_enabled('True'))
