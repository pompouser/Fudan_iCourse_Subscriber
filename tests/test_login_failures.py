"""Login failure classification, without contacting Fudan or using secrets."""

import io
import unittest
from unittest.mock import Mock, patch

import requests

from main import login_with_retry
from src.api.webvpn import (
    LoginRejected,
    WebVPNSession,
    auth_diagnosis,
    password_reminder_skip_payload,
    rejection_message,
)


def _response(status=200, location=""):
    resp = Mock(status_code=status)
    resp.headers = {"Location": location, "Content-Type": "application/json"}
    resp.content = b"{}"
    resp.history = []
    resp.text = ""
    resp.url = "https://webvpn.fudan.edu.cn/"
    return resp


class AuthResponseTests(unittest.TestCase):
    def test_diagnosis_omits_token_and_password(self):
        secret = "A" * 40
        text = auth_diagnosis({
            "code": 200,
            "loginToken": secret,
            "password": "hunter2",
            "message": f"see {secret} please",
            "second": True,
            "moduleCodes": ["userAndSms"],
        })
        self.assertNotIn(secret, text)
        self.assertNotIn("hunter2", text)
        self.assertIn("modules=['userAndSms']", text)
        self.assertIn("[redacted]", text)
        self.assertNotIn("loginToken", text)

    def test_password_error_is_not_retried_by_message(self):
        message = rejection_message({
            "code": "103",
            "message": "用户名或密码错误",
        })
        self.assertIn("UISPSW", message)
        self.assertIn("was not retried", message)

    def test_sms_challenge_names_the_factor(self):
        message = rejection_message({
            "code": "200",
            "second": True,
            "moduleCodes": ["userAndSms"],
            "loginToken": "SHOULD-NOT-LEAK-TOKEN-VALUE",
        })
        self.assertIn("SMS", message)
        self.assertNotIn("SHOULD-NOT-LEAK-TOKEN-VALUE", message)
        self.assertIn("id.fudan.edu.cn", message)

    def test_captcha_message_is_actionable(self):
        message = rejection_message({"code": "200", "message": "请输入验证码"})
        self.assertIn("captcha", message.lower())
        self.assertIn("id.fudan.edu.cn", message)

    def test_skip_payload_matches_official_button(self):
        payload = password_reminder_skip_payload(
            {
                "code": 200,
                "second": True,
                "moduleCodes": ["pwdExpRemd"],
                "authChainCode": "chain-1",
                "requestNumber": "9",
                "userName": "20300000000",
            },
            student_id="20300000000",
            entity_id="https://icourse.fudan.edu.cn",
            lck="lck-value",
            request_type="chain_type",
        )
        self.assertEqual(payload["authModuleCode"], "pwdExpRemd")
        self.assertEqual(payload["authPara"]["isPassRemind"], "yes")
        self.assertNotIn("password", payload["authPara"])
        self.assertEqual(payload["authPara"]["loginName"], "20300000000")


class SessionBehaviorTests(unittest.TestCase):
    def test_reminder_skip_then_token_does_not_log_secrets(self):
        vpn = WebVPNSession()
        reminder = {
            "code": 200,
            "second": True,
            "moduleCodes": ["pwdExpRemd"],
            "authChainCode": "chain-1",
            "requestNumber": "9",
            "userName": "20300000000",
            "message": "密码即将过期",
        }
        posted = []

        def fake_post(payload, *, via_vpn):
            posted.append((payload, via_vpn))
            self.assertNotIn("password", payload.get("authPara", {}))
            return {"code": "200", "loginToken": "SUPERSECRETTOKEN"}

        vpn._post_auth_execute = fake_post
        with patch("sys.stdout", new=io.StringIO()) as stdout:
            token = vpn._accept_login_token(
                reminder,
                via_vpn=True,
                student_id="20300000000",
                entity_id="https://icourse.fudan.edu.cn",
                lck="lck-value",
                request_type="chain_type",
                where="iCourse CAS response",
            )
        self.assertEqual(token, "SUPERSECRETTOKEN")
        self.assertEqual(posted[0][0]["authPara"]["isPassRemind"], "yes")
        self.assertTrue(posted[0][1])
        written = stdout.getvalue()
        self.assertNotIn("SUPERSECRETTOKEN", written)
        self.assertNotIn("20300000000", written)
        self.assertNotIn("lck-value", written)

    def test_sms_challenge_stops(self):
        vpn = WebVPNSession()
        vpn._post_auth_execute = Mock(side_effect=AssertionError("must not post"))
        with self.assertRaises(LoginRejected) as caught:
            vpn._accept_login_token(
                {
                    "code": 200,
                    "second": True,
                    "moduleCodes": ["userAndSms"],
                },
                via_vpn=True,
                student_id="20300000000",
                entity_id="https://icourse.fudan.edu.cn",
                lck="lck-value",
                request_type="chain_type",
                where="iCourse CAS response",
            )
        self.assertIn("SMS", str(caught.exception))
        self.assertNotIn("20300000000", str(caught.exception))

    def test_plain_missing_token_stays_retryable_and_describes_keys(self):
        vpn = WebVPNSession()
        with self.assertRaises(RuntimeError) as caught:
            vpn._accept_login_token(
                {"code": 200, "message": "ok", "data": None},
                via_vpn=False,
                student_id="20300000000",
                entity_id="https://webvpn.fudan.edu.cn",
                lck="lck-value",
                request_type="chain_type",
                where="response",
            )
        text = str(caught.exception)
        self.assertTrue(text.startswith("No loginToken"))
        self.assertIn("code=200", text)
        self.assertNotIn("20300000000", text)
        self.assertNotIsInstance(caught.exception, LoginRejected)

    def test_login_page_200_is_not_a_session(self):
        vpn = WebVPNSession()
        vpn.session.get = Mock(side_effect=[
            _response(200),
            _response(302, "https://webvpn.fudan.edu.cn/login"),
            _response(200),
            _response(302, "https://webvpn.fudan.edu.cn/login"),
            _response(200),
            _response(302, "https://webvpn.fudan.edu.cn/login"),
        ])
        with patch("src.api.webvpn.time.sleep"):
            with self.assertRaises(RuntimeError) as caught:
                vpn._establish_session("https://webvpn.fudan.edu.cn/ticket")
        self.assertIn("was not established", str(caught.exception))
        self.assertEqual(vpn.session.get.call_count, 6)

    def test_portal_200_after_slow_ticket_counts_as_logged_in(self):
        vpn = WebVPNSession()
        vpn.session.get = Mock(side_effect=[
            requests.Timeout("slow"),
            _response(200),
        ])
        with patch("src.api.webvpn.time.sleep"):
            vpn._establish_session("https://webvpn.fudan.edu.cn/ticket")
        self.assertEqual(vpn.session.get.call_count, 2)

    def test_get_retries_timeout_then_returns(self):
        vpn = WebVPNSession()
        ok = _response(200)
        vpn.session.get = Mock(side_effect=[requests.Timeout("reset"), ok])
        with patch("src.api.webvpn.time.sleep"):
            resp = vpn.get("https://icourse.fudan.edu.cn/userapi/v1/infosimple")
        self.assertIs(resp, ok)
        self.assertEqual(vpn.session.get.call_count, 2)
        called_url = vpn.session.get.call_args_list[0].args[0]
        self.assertTrue(called_url.startswith("https://webvpn.fudan.edu.cn/"))


class LoginRetryPolicyTests(unittest.TestCase):
    @patch("main.time.sleep")
    @patch("main.WebVPNSession")
    def test_rejection_is_not_retried(self, session_cls, sleep):
        vpn = session_cls.return_value
        vpn.login.return_value = True
        vpn.authenticate_icourse.side_effect = LoginRejected("captcha required")
        with self.assertRaises(LoginRejected):
            login_with_retry()
        self.assertEqual(vpn.login.call_count, 1)
        sleep.assert_not_called()

    @patch("main.time.sleep")
    @patch("main.WebVPNSession")
    def test_missing_token_stops_after_two_answers(self, session_cls, sleep):
        vpn = session_cls.return_value
        vpn.login.return_value = True
        vpn.authenticate_icourse.side_effect = RuntimeError(
            "No loginToken in iCourse CAS response. code=200; keys=['code']"
        )
        with self.assertRaises(RuntimeError) as caught:
            login_with_retry()
        self.assertIn("no loginToken on two", str(caught.exception))
        self.assertEqual(vpn.login.call_count, 2)
        self.assertIn("code=200", str(caught.exception))

    @patch("main.time.sleep")
    @patch("main.WebVPNSession")
    def test_cold_portal_still_retries(self, session_cls, sleep):
        vpn = session_cls.return_value
        vpn.login.return_value = True
        vpn.authenticate_icourse.side_effect = RuntimeError(
            "WebVPN session is not logged in (portal HTTP 302 to the login page)."
        )
        with self.assertRaises(RuntimeError):
            login_with_retry(max_attempts=3)
        self.assertEqual(vpn.login.call_count, 3)

    @patch("main.time.sleep")
    @patch("main.WebVPNSession")
    def test_missing_credentials_stop_immediately(self, session_cls, sleep):
        vpn = session_cls.return_value
        vpn.login.side_effect = ValueError(
            "Student ID and password are required. Set STUID and UISPsw."
        )
        with self.assertRaises(ValueError):
            login_with_retry()
        self.assertEqual(vpn.login.call_count, 1)
        sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
