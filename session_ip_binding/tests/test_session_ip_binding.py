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


from unittest.mock import MagicMock, patch  # noqa: E402

from odoo.http import SessionExpiredException, root  # noqa: E402
from odoo.tests.common import HttpCase, TransactionCase  # noqa: E402

from ..models.ir_http import _normalize_mode  # noqa: E402

MOD = 'odoo.addons.session_ip_binding.models.ir_http'


class FakeSession(dict):
    uid = 2
    logged_out = False

    def logout(self, keep_db=False):
        self.logged_out = True


@tagged('post_install', '-at_install')
class TestCheckSessionIp(TransactionCase):

    def _check(self, session, ip):
        req = MagicMock()
        req.session = session
        req.env = self.env
        req.httprequest.remote_addr = ip
        req.httprequest.path = '/web'
        with patch(f'{MOD}.request', req), patch(f'{MOD}.root') as root_mock:
            self.env['ir.http']._check_session_ip()
        return root_mock

    def _set(self, **params):
        for k, v in params.items():
            self.env['ir.config_parameter'].sudo().set_param(f'session_ip_binding.{k}', v)

    def test_bind_and_same_ip(self):
        s = FakeSession()
        self._check(s, '10.0.0.1')
        self.assertEqual(s['bound_ip'], '10.0.0.1')
        self._check(s, '10.0.0.1')
        self.assertFalse(s.logged_out)

    def test_different_ip_revokes(self):
        s = FakeSession(bound_ip='10.0.0.1')
        with self.assertLogs(MOD, 'WARNING'), self.assertRaises(SessionExpiredException):
            self._check(s, '10.0.0.2')
        self.assertTrue(s.logged_out)

    def test_rotate_called_on_revoke(self):
        s = FakeSession(bound_ip='10.0.0.1')
        req = MagicMock()
        req.session, req.env = s, self.env
        req.httprequest.remote_addr = '10.0.0.9'
        with patch(f'{MOD}.request', req), patch(f'{MOD}.root') as r, \
                self.assertLogs(MOD, 'WARNING'), self.assertRaises(SessionExpiredException):
            self.env['ir.http']._check_session_ip()
        r.session_store.rotate.assert_called_once_with(s, self.env)

    def test_subnet_ipv4(self):
        self._set(mode='subnet')
        s = FakeSession()
        self._check(s, '10.0.0.1')
        self._check(s, '10.0.0.200')
        with self.assertLogs(MOD, 'WARNING'), self.assertRaises(SessionExpiredException):
            self._check(s, '10.0.1.1')

    def test_subnet_ipv6(self):
        self._set(mode='subnet')
        s = FakeSession()
        self._check(s, '2001:db8:1:2::1')
        self._check(s, '2001:db8:1:2:ffff::9')
        with self.assertLogs(MOD, 'WARNING'), self.assertRaises(SessionExpiredException):
            self._check(s, '2001:db8:1:3::1')

    def test_disabled(self):
        self._set(enabled='False')
        s = FakeSession(bound_ip='10.0.0.1')
        self._check(s, '10.9.9.9')
        self.assertFalse(s.logged_out)
        s2 = FakeSession()
        self._check(s2, '10.9.9.9')
        self.assertNotIn('bound_ip', s2)

    def test_empty_ip_ignored(self):
        for ip in ('', None):
            s = FakeSession(bound_ip='10.0.0.1')
            self._check(s, ip)
            self.assertFalse(s.logged_out)
            s2 = FakeSession()
            self._check(s2, ip)
            self.assertNotIn('bound_ip', s2)

    def test_ipv4_mapped(self):
        self.assertEqual(_network_key('::ffff:1.2.3.4', 'exact'), '1.2.3.4')
        self.assertEqual(_network_key('::ffff:1.2.3.4', 'subnet'), '1.2.3.0/24')
        s = FakeSession()
        self._check(s, '1.2.3.4')
        self._check(s, '::ffff:1.2.3.4')
        self.assertFalse(s.logged_out)

    def test_invalid_mode_is_exact(self):
        self.assertEqual(_normalize_mode('bogus'), 'exact')
        self.assertEqual(_normalize_mode(None), 'exact')
        self.assertEqual(_normalize_mode('subnet'), 'subnet')
        self._set(mode='bogus')
        s = FakeSession()
        self._check(s, '10.0.0.1')
        with self.assertLogs(MOD, 'WARNING'), self.assertRaises(SessionExpiredException):
            self._check(s, '10.0.0.2')


@tagged('post_install', '-at_install')
class TestSettings(TransactionCase):

    def test_seeded_params(self):
        icp = self.env['ir.config_parameter'].sudo()
        self.assertEqual(icp.get_param('session_ip_binding.enabled'), 'True')
        self.assertEqual(icp.get_param('session_ip_binding.mode'), 'exact')

    def test_defaults(self):
        defaults = self.env['res.config.settings'].default_get(
            ['session_ip_binding_enabled', 'session_ip_binding_mode'])
        self.assertTrue(defaults['session_ip_binding_enabled'])
        self.assertEqual(defaults['session_ip_binding_mode'], 'exact')

    def test_execute(self):
        self.env = self.env(user=self.env.ref('base.user_admin'))
        settings = self.env['res.config.settings'].create({
            'session_ip_binding_enabled': False,
            'session_ip_binding_mode': 'subnet',
        })
        settings.execute()
        icp = self.env['ir.config_parameter'].sudo()
        self.assertFalse(_param_enabled(icp.get_param('session_ip_binding.enabled')))
        self.assertEqual(icp.get_param('session_ip_binding.mode'), 'subnet')


@tagged('post_install', '-at_install')
class TestSessionIpBindingHttp(HttpCase):

    def test_end_to_end(self):
        self.authenticate('admin', 'admin')
        sid = self.session.sid
        self.assertEqual(self.url_open('/web').status_code, 200)
        stored = root.session_store.get(sid)
        self.assertTrue(stored.get('bound_ip'))
        self.assertEqual(self.url_open('/web', allow_redirects=False).status_code, 200)
        stored['bound_ip'] = '203.0.113.77'
        root.session_store.save(stored)
        with self.assertLogs(MOD, 'WARNING'):
            res = self.url_open('/web', allow_redirects=False)
        self.assertIn(res.status_code, (302, 303))
        self.assertIn('/web/login', res.headers.get('Location', ''))
        self.assertFalse(root.session_store.get(sid).uid)
