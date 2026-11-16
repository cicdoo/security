from odoo.tests.common import TransactionCase, tagged


@tagged('post_install', '-at_install')
class TestSettings(TransactionCase):

    def test_data_defaults(self):
        icp = self.env['ir.config_parameter'].sudo()
        self.assertTrue(icp.get_bool('session_ip_binding.enabled', False))
        self.assertEqual(icp.get_str('session_ip_binding.mode', ''), 'exact')

    def test_settings_roundtrip(self):
        icp = self.env['ir.config_parameter'].sudo()
        settings = self.env['res.config.settings'].create({
            'session_ip_binding_enabled': False,
            'session_ip_binding_mode': 'subnet',
        })
        settings.execute()
        self.assertFalse(icp.get_bool('session_ip_binding.enabled', True))
        self.assertEqual(icp.get_str('session_ip_binding.mode', ''), 'subnet')
        fresh = self.env['res.config.settings'].create({})
        self.assertFalse(fresh.session_ip_binding_enabled)
        self.assertEqual(fresh.session_ip_binding_mode, 'subnet')

    def test_view_has_fields(self):
        arch = self.env['res.config.settings'].get_view(
            self.env.ref('base_setup.res_config_settings_view_form').id)['arch']
        self.assertIn('session_ip_binding_enabled', arch)
        self.assertIn('session_ip_binding_mode', arch)
