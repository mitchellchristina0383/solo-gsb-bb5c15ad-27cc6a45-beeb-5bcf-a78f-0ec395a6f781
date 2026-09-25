import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mailtrace.parsing import analyze_auth_results  # noqa: E402
from mailtrace.parsing.sample import (  # noqa: E402
    SAMPLE_HEADERS_AUTHRES,
    SAMPLE_TRUSTED_HOSTS,
)

try:  # Flask 相关测试在未安装 Flask 时跳过（解析核心仅需标准库）
    from app import create_app
except ImportError:  # pragma: no cover
    create_app = None


def _received(frm, by, ip=None, date="Thu, 24 Sep 2026 03:00:00 +0000"):
    """构造单条 Received（书写顺序即最终接收方在顶部）。"""
    head = f"Received: from {frm}"
    if ip:
        head += f" ({frm} [{ip}])"
    head += f"\n\tby {by} with ESMTP id X"
    if date:
        head += f"; {date}"
    return head


def _ar(authserv, *methods):
    """构造单条 Authentication-Results 字段；authserv 为 None 时省略标识。"""
    head = "Authentication-Results:"
    if authserv is not None:
        head += f" {authserv}"
    if methods:
        head += "; " + "; ".join(methods)
    return head


# 头部自上而下（书写顺序）：
#   AR(edge.org)            -> 第 1 跳（可信，身份一致）   本组织声明
#   AR(mail.other)          -> 第 1 跳（可信，身份不符）   身份不符
#   Received by edge.org    第 1 跳 可信
#   AR(gw2.org)             -> 第 2 跳（可信，身份一致）   本组织声明
#   Received by gw2.org     第 2 跳 可信
#   AR(forged.example)      -> 第 3 跳（可信边界）         越过边界
#   Received by relay.out   第 3 跳 边界（未命中名单）
#   AR(gw2.org)             -> 第 4 跳（边界之后再次命中） 越过边界
#   Received by gw2.org     第 4 跳 边界之外（不重新接入）
#   Received by sender.out  第 5 跳 边界之外
#   AR(edge.external)       -> 其后没有 Received           无对应跳
HEADERS = "\n".join(
    [
        _ar(
            "edge.org",
            "spf=pass smtp.mailfrom=x.example",
            "dkim=pass header.d=x.example",
            "dkim=fail header.d=evil.example",
            "dmarc=pass header.from=x.example",
        ),
        _ar("mail.other", "spf=pass smtp.mailfrom=x.example"),
        _received("gw2.org", "edge.org", "10.0.0.2"),
        _ar("gw2.org", "spf=softfail smtp.mailfrom=x.example", "dmarc=none"),
        _received("partner.example", "gw2.org", "203.0.113.55"),
        _ar("forged.example", "spf=pass", "dmarc=pass"),
        _received("relay.out", "relay.out", "198.51.100.9"),
        _ar("gw2.org", "spf=pass"),
        _received("sender.out", "gw2.org", "198.51.100.8"),
        _received("sender.out", "sender.out", "192.0.2.5"),
        _ar("edge.external", "spf=fail"),
        "Subject: hi\n",
    ]
)
HOSTS = ["edge.org", "gw2.org"]


class AuthResultsAttributionTests(unittest.TestCase):
    def test_empty_hostlist_is_input_error(self):
        result = analyze_auth_results(HEADERS, "  \n, ")
        self.assertIn("error", result)
        self.assertNotIn("fields", result)

    def test_status_counts_and_trust_reuse(self):
        result = analyze_auth_results(HEADERS, HOSTS)
        self.assertEqual(result["status"], "found")
        self.assertEqual(result["status_label"], "有本组织声明")
        self.assertEqual(result["trust_status"], "established")
        self.assertEqual(result["trusted_count"], 2)
        self.assertEqual(result["ar_total"], 6)
        self.assertEqual(result["org_claim_count"], 2)
        self.assertEqual(result["boundary"]["top_index"], 3)

    def test_org_claim_results_keep_order_and_duplicates(self):
        result = analyze_auth_results(HEADERS, HOSTS)
        first = result["fields"][0]
        self.assertEqual(first["attribution"], "org_claim")
        self.assertEqual(first["attribution_label"], "本组织声明")
        self.assertEqual(first["hop_top_index"], 1)
        self.assertEqual(first["hop_by"], "edge.org")
        self.assertTrue(first["hop_trusted"])
        # 按原文顺序保留，两个 dkim 结果不去重
        self.assertEqual(
            first["results"],
            [
                {"method": "spf", "result": "pass"},
                {"method": "dkim", "result": "pass"},
                {"method": "dkim", "result": "fail"},
                {"method": "dmarc", "result": "pass"},
            ],
        )

    def test_identity_mismatch_on_trusted_hop(self):
        result = analyze_auth_results(HEADERS, HOSTS)
        second = result["fields"][1]
        self.assertEqual(second["attribution"], "identity_mismatch")
        self.assertEqual(second["attribution_label"], "身份不符")
        self.assertEqual(second["hop_top_index"], 1)
        self.assertTrue(second["hop_trusted"])
        self.assertEqual(second["authserv_id"], "mail.other")
        # 非本组织声明不提取结果词
        self.assertEqual(second["results"], [])

    def test_ar_between_received_maps_to_hop_below(self):
        # 位于两条 Received 之间的 AR 归属到其下方紧邻的一跳，而不是上方
        result = analyze_auth_results(HEADERS, HOSTS)
        third = result["fields"][2]
        self.assertEqual(third["attribution"], "org_claim")
        self.assertEqual(third["hop_top_index"], 2)
        self.assertEqual(third["hop_by"], "gw2.org")
        self.assertEqual(
            third["results"],
            [
                {"method": "spf", "result": "softfail"},
                {"method": "dmarc", "result": "none"},
            ],
        )

    def test_beyond_boundary_at_boundary_and_reentry(self):
        result = analyze_auth_results(HEADERS, HOSTS)
        fourth = result["fields"][3]
        self.assertEqual(fourth["attribution"], "beyond_boundary")
        self.assertEqual(fourth["attribution_label"], "越过边界")
        self.assertEqual(fourth["hop_top_index"], 3)
        self.assertFalse(fourth["hop_trusted"])
        # 第 5 条：authserv-id 虽与第 4 跳 by 一致，但该跳在边界之外
        fifth = result["fields"][4]
        self.assertEqual(fifth["attribution"], "beyond_boundary")
        self.assertEqual(fifth["hop_top_index"], 4)
        self.assertEqual(fifth["hop_by"], "gw2.org")
        self.assertFalse(fifth["hop_trusted"])

    def test_no_hop_when_no_received_below(self):
        result = analyze_auth_results(HEADERS, HOSTS)
        last = result["fields"][5]
        self.assertEqual(last["attribution"], "no_hop")
        self.assertEqual(last["attribution_label"], "无对应跳")
        self.assertIsNone(last["hop_top_index"])
        self.assertIsNone(last["hop_by"])
        self.assertIsNone(last["hop_trusted"])

    def test_claims_are_org_claim_fields_in_order(self):
        result = analyze_auth_results(HEADERS, HOSTS)
        self.assertEqual([c["ar_index"] for c in result["claims"]], [1, 3])

    def test_duplicate_ar_fields_both_become_claims(self):
        raw = "\n".join(
            [
                _ar("edge.org", "spf=pass"),
                _ar("edge.org", "spf=fail"),
                _received("gw2.org", "edge.org"),
            ]
        )
        result = analyze_auth_results(raw, HOSTS)
        self.assertEqual(result["org_claim_count"], 2)
        self.assertEqual(
            [c["results"] for c in result["claims"]],
            [
                [{"method": "spf", "result": "pass"}],
                [{"method": "spf", "result": "fail"}],
            ],
        )

    def test_authserv_id_case_and_trailing_dot_ignored(self):
        raw = "\n".join(
            [
                _ar("EDGE.ORG.", "spf=pass"),
                _received("gw2.org", "edge.org"),
            ]
        )
        result = analyze_auth_results(raw, HOSTS)
        self.assertEqual(result["fields"][0]["attribution"], "org_claim")

    def test_missing_authserv_id_is_identity_mismatch(self):
        raw = "\n".join(
            [
                _ar(None, "spf=pass"),
                _received("gw2.org", "edge.org"),
            ]
        )
        result = analyze_auth_results(raw, HOSTS)
        field = result["fields"][0]
        self.assertIsNone(field["authserv_id"])
        self.assertEqual(field["attribution"], "identity_mismatch")
        self.assertIn("缺少 authserv-id", field["detail"])

    def test_first_segment_method_spec_means_no_authserv_id(self):
        raw = "\n".join(
            [
                "Authentication-Results: spf=pass; dkim=fail",
                _received("gw2.org", "edge.org"),
            ]
        )
        result = analyze_auth_results(raw, HOSTS)
        field = result["fields"][0]
        self.assertIsNone(field["authserv_id"])
        self.assertEqual(field["attribution"], "identity_mismatch")

    def test_authserv_none_means_no_authserv_id(self):
        raw = "\n".join(
            [
                "Authentication-Results: none",
                _received("gw2.org", "edge.org"),
            ]
        )
        result = analyze_auth_results(raw, HOSTS)
        self.assertIsNone(result["fields"][0]["authserv_id"])
        self.assertEqual(
            result["fields"][0]["attribution"], "identity_mismatch"
        )

    def test_untrusted_top_means_no_org_claims(self):
        result = analyze_auth_results(HEADERS, ["nope.org"])
        self.assertEqual(result["status"], "none")
        self.assertEqual(result["status_label"], "无本组织声明")
        self.assertEqual(result["trust_status"], "untrusted_top")
        self.assertEqual(result["org_claim_count"], 0)
        self.assertEqual(result["claims"], [])
        self.assertIn("无本组织声明", result["message"])
        # 有对应跳的均为越过边界，最后一条无对应跳
        attributions = [f["attribution"] for f in result["fields"]]
        self.assertEqual(
            attributions,
            ["beyond_boundary"] * 5 + ["no_hop"],
        )

    def test_no_received_means_no_org_claims(self):
        raw = _ar("edge.org", "spf=pass") + "\nSubject: hi\n"
        result = analyze_auth_results(raw, HOSTS)
        self.assertEqual(result["status"], "none")
        self.assertEqual(result["trust_status"], "no_received")
        self.assertEqual(result["org_claim_count"], 0)
        self.assertEqual(result["fields"][0]["attribution"], "no_hop")
        self.assertIn("无本组织声明", result["message"])

    def test_no_ar_fields(self):
        raw = "\n".join(
            [
                _received("gw2.org", "edge.org"),
                _received("mail.corp", "gw2.org"),
            ]
        )
        result = analyze_auth_results(raw, HOSTS)
        self.assertEqual(result["status"], "none")
        self.assertEqual(result["ar_total"], 0)
        self.assertEqual(result["org_claim_count"], 0)
        self.assertEqual(result["fields"], [])
        self.assertIn("没有 Authentication-Results 字段", result["message"])

    def test_only_tracked_methods_extracted(self):
        raw = "\n".join(
            [
                _ar(
                    "edge.org",
                    "iprev=pass policy.iprev=192.0.2.1",
                    "auth=pass (details)",
                    "spf=pass smtp.mailfrom=x.example",
                    "dkim=temperror header.d=x.example",
                    "dmarc=permerror header.from=x.example",
                    "sender-id=pass",
                ),
                _received("gw2.org", "edge.org"),
            ]
        )
        result = analyze_auth_results(raw, HOSTS)
        self.assertEqual(
            result["fields"][0]["results"],
            [
                {"method": "spf", "result": "pass"},
                {"method": "dkim", "result": "temperror"},
                {"method": "dmarc", "result": "permerror"},
            ],
        )

    def test_method_names_case_insensitive_result_word_preserved(self):
        raw = "\n".join(
            [
                _ar("edge.org", "SPF=Pass", "DKIM=FAIL", "Dmarc=None"),
                _received("gw2.org", "edge.org"),
            ]
        )
        result = analyze_auth_results(raw, HOSTS)
        self.assertEqual(
            result["fields"][0]["results"],
            [
                {"method": "spf", "result": "Pass"},
                {"method": "dkim", "result": "FAIL"},
                {"method": "dmarc", "result": "None"},
            ],
        )

    def test_string_hostlist_with_commas(self):
        result = analyze_auth_results(HEADERS, "edge.org, gw2.org")
        self.assertEqual(result["org_claim_count"], 2)

    def test_field_position_counts_all_header_fields(self):
        result = analyze_auth_results(HEADERS, HOSTS)
        # 第 1、2 条 AR 是头部第 1、2 个字段
        self.assertEqual(result["fields"][0]["field_position"], 1)
        self.assertEqual(result["fields"][1]["field_position"], 2)
        # 第 3 条 AR 之前有一条 Received
        self.assertEqual(result["fields"][2]["field_position"], 4)

    def test_sample_headers_attribution(self):
        result = analyze_auth_results(
            SAMPLE_HEADERS_AUTHRES, SAMPLE_TRUSTED_HOSTS
        )
        self.assertEqual(result["status"], "found")
        self.assertEqual(result["ar_total"], 6)
        self.assertEqual(result["org_claim_count"], 2)
        self.assertEqual(
            [f["attribution"] for f in result["fields"]],
            [
                "org_claim",
                "identity_mismatch",
                "org_claim",
                "beyond_boundary",
                "beyond_boundary",
                "no_hop",
            ],
        )
        first = result["claims"][0]
        self.assertEqual(first["authserv_id"], "edge.internal.corp")
        self.assertEqual(
            first["results"],
            [
                {"method": "spf", "result": "pass"},
                {"method": "dkim", "result": "pass"},
                {"method": "dkim", "result": "fail"},
                {"method": "dmarc", "result": "pass"},
            ],
        )


@unittest.skipIf(create_app is None, "Flask 未安装")
class AuthResultsApiTests(unittest.TestCase):
    def setUp(self):
        self.client = create_app().test_client()

    def test_api_json_found(self):
        resp = self.client.post(
            "/api/analyze/auth-results",
            json={"headers": HEADERS, "trusted_hosts": HOSTS},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "found")
        self.assertEqual(data["org_claim_count"], 2)
        self.assertEqual(
            data["claims"][0]["results"][1],
            {"method": "dkim", "result": "pass"},
        )

    def test_api_empty_hostlist_400(self):
        resp = self.client.post(
            "/api/analyze/auth-results",
            json={"headers": HEADERS, "trusted_hosts": []},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("名单不能为空", resp.get_json()["error"])

    def test_api_untrusted_top_is_200(self):
        resp = self.client.post(
            "/api/analyze/auth-results",
            json={"headers": HEADERS, "trusted_hosts": ["nope.org"]},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "none")
        self.assertEqual(data["trust_status"], "untrusted_top")

    def test_api_no_received_is_200(self):
        resp = self.client.post(
            "/api/analyze/auth-results",
            json={"headers": "Subject: hi\n", "trusted_hosts": HOSTS},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["trust_status"], "no_received")

    def test_api_blank_headers_400(self):
        resp = self.client.post(
            "/api/analyze/auth-results",
            json={"headers": "   ", "trusted_hosts": HOSTS},
        )
        self.assertEqual(resp.status_code, 400)

    def test_api_bad_trusted_hosts_type_400(self):
        resp = self.client.post(
            "/api/analyze/auth-results",
            json={"headers": HEADERS, "trusted_hosts": [1, 2]},
        )
        self.assertEqual(resp.status_code, 400)

    def test_api_trusted_hosts_wrong_scalar_type_400(self):
        resp = self.client.post(
            "/api/analyze/auth-results",
            json={"headers": HEADERS, "trusted_hosts": 9},
        )
        self.assertEqual(resp.status_code, 400)

    def test_api_headers_wrong_type_400(self):
        resp = self.client.post(
            "/api/analyze/auth-results",
            json={"headers": 5, "trusted_hosts": HOSTS},
        )
        self.assertEqual(resp.status_code, 400)

    def test_api_form_encoded(self):
        resp = self.client.post(
            "/api/analyze/auth-results",
            data={"headers": HEADERS, "trusted_hosts": "edge.org\ngw2.org"},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["org_claim_count"], 2)

    def test_page_form_renders(self):
        resp = self.client.post(
            "/auth-results",
            data={"headers_authres": HEADERS, "authres_hosts": "edge.org\ngw2.org"},
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.get_data(as_text=True)
        self.assertIn("认证结果来源", body)
        self.assertIn("本组织声明", body)
        self.assertIn("dkim=fail", body)
        self.assertIn("越过边界", body)
        self.assertIn("无对应跳", body)

    def test_page_form_empty_hostlist_error_banner(self):
        resp = self.client.post(
            "/auth-results",
            data={"headers_authres": HEADERS, "authres_hosts": "  "},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("名单不能为空", resp.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
