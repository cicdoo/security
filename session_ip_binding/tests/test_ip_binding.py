from unittest.mock import MagicMock, patch

from odoo.http import root, SessionExpiredException
from odoo.tests.common import HttpCase, TransactionCase, tagged

from odoo.addons.session_ip_binding.models import ir_http
from odoo.addons.session_ip_binding.models.ir_http import IrHttp, _network_key


class FakeSession(dict):
    uid = 7

    def logout(self, keep_db=False):
        pass


@tagged('post_install', '-at_install')
class TestIpBinding(TransactionCase):

    def _req(self, session, ip):
        req = MagicMock()
        req.session = session
        req.env = self.env
        req.httprequest.remote_addr = ip
        req.httprequest.path = '/x'
        with patch.object(ir_http, 'request', req), \
                patch.object(ir_http, 'root'):
            IrHttp._check_session_ip()

    def test_key(self):
        self.assertEqual(_network_key('1.2.3.4', 'exact'), ('v4', '1.2.3.4'))
        self.assertEqual(_network_key('1.2.3.4', 'subnet'), ('v4', '1.2.3.0/24'))
        self.assertEqual(_network_key('::ffff:1.2.3.4', 'exact'), ('v4', '1.2.3.4'))
        self.assertEqual(_network_key('2001:db8:1:2:3:4:5:6', 'exact'),
                         ('v6', '2001:db8:1:2::/64'))
        self.assertEqual(_network_key('junk', 'exact'), ('raw', 'junk'))

    def test_family_switch_ok(self):
        s = FakeSession()
        for ip in ('1.2.3.4', '2001:db8::1', '1.2.3.4', '2001:db8::2'):
            self._req(s, ip)

    def test_v4_change_revokes(self):
        s = FakeSession()
        self._req(s, '1.2.3.4')
        with self.assertRaises(SessionExpiredException):
            self._req(s, '1.2.3.5')

    def test_v6_prefix(self):
        s = FakeSession()
        self._req(s, '2001:db8:1:2::1')
        self._req(s, '2001:db8:1:2::ffff')
        with self.assertRaises(SessionExpiredException):
            self._req(s, '2001:db8:1:3::1')

    def test_legacy_migration_exact(self):
        s = FakeSession(bound_ip='1.2.3.4')
        self._req(s, '1.2.3.4')
        self.assertNotIn('bound_ip', s)
        self.assertEqual(s['bound_ip_v4'], '1.2.3.4')
        with self.assertRaises(SessionExpiredException):
            self._req(s, '1.2.3.5')
        s = FakeSession(bound_ip='2001:db8:1:2::1')
        self._req(s, '2001:db8:1:2::9')
        self.assertEqual(s['bound_ip_v6'], '2001:db8:1:2::/64')

    def test_legacy_migration_cidr(self):
        self.env['ir.config_parameter'].set_param('session_ip_binding.mode', 'subnet')
        s = FakeSession(bound_ip='10.1.2.0/24')
        self._req(s, '10.1.2.77')
        self.assertEqual(s['bound_ip_v4'], '10.1.2.0/24')
        self.assertNotIn('bound_ip', s)
        s = FakeSession(bound_ip='2001:db8:1:2::/64')
        self._req(s, '2001:db8:1:2::5')
        self.assertEqual(s['bound_ip_v6'], '2001:db8:1:2::/64')
        self.assertNotIn('bound_ip_v4', s)

    def test_legacy_cidr_in_exact_mode_not_logged_out(self):
        s = FakeSession(bound_ip='10.1.2.0/24')
        self._req(s, '10.1.2.77')
        self.assertEqual(s['bound_ip_v4'], '10.1.2.77')

    def test_mapped_is_v4(self):
        s = FakeSession()
        self._req(s, '1.2.3.4')
        self._req(s, '::ffff:1.2.3.4')
        with self.assertRaises(SessionExpiredException):
            self._req(s, '::ffff:1.2.3.9')

    def test_subnet_mode(self):
        self.env['ir.config_parameter'].set_param('session_ip_binding.mode', 'subnet')
        s = FakeSession()
        self._req(s, '1.2.3.4')
        self._req(s, '1.2.3.99')
        with self.assertRaises(SessionExpiredException):
            self._req(s, '1.2.4.1')

    def test_disabled(self):
        self.env['ir.config_parameter'].set_param('session_ip_binding.enabled', 'False')
        s = FakeSession()
        self._req(s, '1.2.3.4')
        self._req(s, '5.6.7.8')
        self.assertEqual(s, {})


@tagged('post_install', '-at_install')
class TestSessionIpBinding(HttpCase):

    def test_ip_change_revokes_session(self):
        icp = self.env['ir.config_parameter']
        icp.set_param('session_ip_binding.enabled', 'True')
        icp.set_param('session_ip_binding.mode', 'exact')
        self.env.cr.flush()
        self.authenticate('admin', 'admin')
        sid = self.opener.cookies['session_id']
        res = self.url_open('/odoo', allow_redirects=False)
        self.assertEqual(res.status_code, 200)
        session = root.session_store.get(sid)
        self.assertTrue(session.get('bound_ip_v4'))
        session['bound_ip_v4'] = '203.0.113.99'
        root.session_store.save(session)
        res = self.url_open('/odoo', allow_redirects=False)
        self.assertEqual(res.status_code, 303)
        self.assertIn('/web/login', res.headers['Location'])
