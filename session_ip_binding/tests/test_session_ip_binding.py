from odoo.tests import HttpCase, tagged

from ..models.ir_http import _network_key


@tagged('post_install', '-at_install')
class TestSessionIpBinding(HttpCase):


    def test_network_key(self):
        self.assertEqual(_network_key('10.1.2.3', 'exact'), '10.1.2.3')
        self.assertEqual(_network_key('10.1.2.3', 'subnet'), '10.1.2.0/24')
        self.assertEqual(_network_key('2001:db8::1', 'subnet'), '2001:db8::/64')
        self.assertEqual(_network_key('bogus', 'subnet'), 'bogus')

    def test_param_defaults(self):
        icp = self.env['ir.config_parameter']
        self.assertEqual(icp.get_param('session_ip_binding.enabled'), 'True')
        self.assertEqual(icp.get_param('session_ip_binding.mode'), 'exact')
