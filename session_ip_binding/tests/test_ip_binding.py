import logging
from unittest.mock import MagicMock, patch

from odoo.http.session import SessionExpiredException
from odoo.tests.common import TransactionCase, tagged

from odoo.addons.session_ip_binding.models import ir_http
from odoo.addons.session_ip_binding.models.ir_http import IrHttp, _network_key


class FakeSession(dict):
    uid = 7


@tagged('post_install', '-at_install')
class TestIpBinding(TransactionCase):

    def _req(self, session, ip, logout=None, store=None):
        req = MagicMock()
        req.session = session
        req.env = self.env
        req.httprequest.remote_addr = ip
        req.httprequest.path = '/x'
        with patch.object(ir_http, 'request', req), \
                patch.object(ir_http, 'logout', logout or MagicMock()), \
                patch.object(ir_http, 'session_store', store or MagicMock()):
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

    def test_legacy_migration(self):
        s = FakeSession(bound_ip='1.2.3.4')
        self._req(s, '1.2.3.4')
        self.assertNotIn('bound_ip', s)
        self.assertEqual(s['bound_ip_v4'], '1.2.3.4')
        s = FakeSession(bound_ip='2001:db8:1:2::1')
        self._req(s, '2001:db8:1:2::9')
        self.assertEqual(s['bound_ip_v6'], '2001:db8:1:2::/64')

    def test_mapped_is_v4(self):
        s = FakeSession()
        self._req(s, '1.2.3.4')
        self._req(s, '::ffff:1.2.3.4')
        with self.assertRaises(SessionExpiredException):
            self._req(s, '::ffff:1.2.3.9')

    def test_subnet_mode(self):
        self.env['ir.config_parameter'].set_str('session_ip_binding.mode', 'subnet')
        s = FakeSession()
        self._req(s, '1.2.3.4')
        self._req(s, '1.2.3.99')
        with self.assertRaises(SessionExpiredException):
            self._req(s, '1.2.4.1')

    def test_disabled(self):
        self.env['ir.config_parameter'].set_bool('session_ip_binding.enabled', False)
        s = FakeSession()
        self._req(s, '1.2.3.4')
        self._req(s, '5.6.7.8')
        self.assertEqual(s, {})

    def test_key_edge_cases(self):
        self.assertEqual(_network_key('', 'exact'), ('raw', ''))
        # Python >= 3.9 parses zone IDs; the zone is dropped by the /64 reduction
        self.assertEqual(_network_key('fe80::1%eth0', 'exact'), ('v6', 'fe80::/64'))
        self.assertEqual(_network_key('::ffff:1.2.3.4', 'subnet'), ('v4', '1.2.3.0/24'))
        self.assertEqual(_network_key('2001:db8:1:2:ffff:ffff:ffff:ffff', 'exact'),
                         ('v6', '2001:db8:1:2::/64'))
        self.assertEqual(_network_key('2001:db8:1:3::', 'exact'),
                         ('v6', '2001:db8:1:3::/64'))
        self.assertEqual(_network_key('1.2.3.4', 'bogus'), ('v4', '1.2.3.4'))

    def test_empty_remote_addr_binds_raw(self):
        s = FakeSession()
        self._req(s, '')
        self.assertEqual(s, {'bound_ip_raw': ''})
        self._req(s, '')
        with self.assertRaises(SessionExpiredException):
            self._req(s, 'junk')

    def test_revocation_calls_logout_and_rotate_once(self):
        s = FakeSession()
        self._req(s, '1.2.3.4')
        logout, store = MagicMock(), MagicMock()
        with self.assertLogs(ir_http._logger, logging.WARNING) as logs, \
                self.assertRaises(SessionExpiredException):
            self._req(s, '1.2.3.5', logout=logout, store=store)
        logout.assert_called_once_with(s, keep_db=True)
        store.return_value.rotate.assert_called_once()
        self.assertIn('session revoked', logs.output[0])

    def test_legacy_does_not_overwrite_family_key(self):
        s = FakeSession(bound_ip='1.2.3.4', bound_ip_v4='1.2.3.9')
        with self.assertRaises(SessionExpiredException):
            self._req(s, '1.2.3.4')
        self.assertEqual(s['bound_ip_v4'], '1.2.3.9')
        self.assertNotIn('bound_ip', s)

    def test_first_request_binds_then_no_more_writes(self):
        s = FakeSession()
        self._req(s, '1.2.3.4')
        self.assertEqual(s, {'bound_ip_v4': '1.2.3.4'})
        snapshot = dict(s)
        self._req(s, '1.2.3.4')
        self.assertEqual(s, snapshot)

    def test_cross_family_theft_pinned(self):
        """Documented trade-off: the other family binds freely, the original
        family stays protected."""
        s = FakeSession()
        self._req(s, '1.2.3.4')
        self._req(s, '2001:db8::1')  # accepted, binds v6
        self.assertEqual(set(s), {'bound_ip_v4', 'bound_ip_v6'})
        with self.assertRaises(SessionExpiredException):
            self._req(s, '1.2.3.9')
