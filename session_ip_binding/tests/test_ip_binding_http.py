from unittest.mock import patch

from werkzeug.wrappers import Request as WerkzeugRequest

from odoo.tests.common import HttpCase, tagged

ROUTE = '/web/session/check'


@tagged('post_install', '-at_install')
class TestIpBindingHttp(HttpCase):
    """Real request path through ``ir.http._authenticate_explicit``."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.user = cls.env['res.users'].create({
            'name': 'IP binding user',
            'login': 'ip_binding_user',
            'password': 'ip_binding_user_pw!',
            'group_ids': [(6, 0, [cls.env.ref('base.group_user').id])],
        })
        cls.client_ip = '1.2.3.4'

    def _call(self, ip, session_cookie=None):
        """POST the route as seen from ``ip``; returns the JSON-RPC response."""
        self.client_ip = ip
        cookies = {'session_id': session_cookie} if session_cookie else None
        return self.url_open(
            ROUTE, data='{"jsonrpc": "2.0", "method": "call", "params": {}}',
            headers={'Content-Type': 'application/json'}, cookies=cookies)

    def _ok(self, response):
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('error', response.json())

    def _rejected(self, response):
        self.assertTrue(
            response.status_code != 200 or 'error' in response.json(),
            "request should have been rejected")

    def setUp(self):
        super().setUp()
        test = self
        orig_init = WerkzeugRequest.__init__

        def __init__(self, *args, **kwargs):
            orig_init(self, *args, **kwargs)
            self.remote_addr = test.client_ip

        patcher = patch.object(WerkzeugRequest, '__init__', __init__)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.client_ip = '1.2.3.4'
        self.authenticate(self.user.login, 'ip_binding_user_pw!')

    def _sid(self):
        return self.session.sid

    def test_same_ip_accepted(self):
        self._ok(self._call('1.2.3.4'))
        self._ok(self._call('1.2.3.4'))

    def test_changed_ip_revokes_session(self):
        sid = self._sid()
        self._ok(self._call('1.2.3.4'))
        self._rejected(self._call('1.2.3.5'))
        # the old cookie is dead even from the original address
        r = self._call('1.2.3.4', session_cookie=sid)
        self._rejected(r)

    def test_dual_stack_switch_accepted(self):
        self._ok(self._call('1.2.3.4'))
        self._ok(self._call('2001:db8::1'))
        self._ok(self._call('1.2.3.4'))
        self._ok(self._call('2001:db8::2'))

    def test_cross_family_theft_is_accepted_but_family_stays_bound(self):
        """Documented trade-off: other family binds, original stays protected."""
        self._ok(self._call('1.2.3.4'))
        self._ok(self._call('2001:db8::1'))
        self._rejected(self._call('1.2.3.9'))

    def test_disabled_setting_skips_check(self):
        self.env['ir.config_parameter'].sudo().set_bool(
            'session_ip_binding.enabled', False)
        self._ok(self._call('1.2.3.4'))
        self._ok(self._call('9.9.9.9'))
