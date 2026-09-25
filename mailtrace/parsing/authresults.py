"""Authentication-Results 字段的来源归属（复用折行展开与可信边界分析）。

归属口径：
- 复用 :func:`mailtrace.parsing.parser.parse_header_blocks` 的折行展开，
  按原文顺序收集所有 ``Authentication-Results`` 字段（字段名大小写不敏感）。
- 每条 Authentication-Results 归属到**其后紧邻的 Received**：头部书写顺序中
  它之后的第一条 Received（即两者之间不得有另一条 Received）。该 Received
  的 ``by`` 主机即写下这条认证结果的接收服务器；之后没有任何 Received 的
  字段标记为“无对应跳”。
- 复用 :func:`mailtrace.parsing.trust.analyze_trust_boundary` 的可信边界
  结果：对应跳必须属于**自顶端连续可信前缀**（trusted=true）；边界跳本身
  与边界之后的跳均不可信，对应字段标记为“越过边界”。
- 可信跳的 ``by`` 主机还须与字段的 **authserv-id** 一致（忽略大小写与
  末尾点）；不一致或缺失 authserv-id 时标记为“身份不符”。三项条件全部
  满足才标为“本组织声明”。
- 仅对本组织声明提取 spf / dkim / dmarc 的结果词，**按原文顺序保留，
  重复声明不去重**；其余字段的 ``results`` 为空数组。没有可信前缀
  （顶端未命中名单或没有 Received）时整体 ``status`` 为 ``none``，
  明确“无本组织声明”。
"""

from __future__ import annotations

import bisect
import re

from mailtrace.parsing.parser import parse_header_blocks
from mailtrace.parsing.trust import (
    STATUS_NO_RECEIVED,
    STATUS_UNTRUSTED_TOP,
    analyze_trust_boundary,
    normalize_host,
)

AR_FIELD_NAME = "authentication-results"
RECEIVED_FIELD_NAME = "received"

# 归属结论
ATTR_ORG_CLAIM = "org_claim"
ATTR_NO_HOP = "no_hop"
ATTR_BEYOND_BOUNDARY = "beyond_boundary"
ATTR_IDENTITY_MISMATCH = "identity_mismatch"

_ATTR_LABELS = {
    ATTR_ORG_CLAIM: "本组织声明",
    ATTR_NO_HOP: "无对应跳",
    ATTR_BEYOND_BOUNDARY: "越过边界",
    ATTR_IDENTITY_MISMATCH: "身份不符",
}

STATUS_FOUND = "found"
STATUS_NONE = "none"

_STATUS_LABELS = {
    STATUS_FOUND: "有本组织声明",
    STATUS_NONE: "无本组织声明",
}

# 只提取这三种方法的结果词
_TRACKED_METHODS = ("spf", "dkim", "dmarc")

# 方法声明：method=result（结果词取等号后第一个空白 / 分号前的内容）
_METHOD_RESULT_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9-]*)\s*=\s*([^\s;]+)")


def _parse_ar_value(value: str) -> tuple[str | None, list[dict]]:
    """解析 Authentication-Results 字段值。

    返回 ``(authserv_id, results)``：authserv_id 为第一个分号前的标识
    （缺失、为空或为 ``none`` 时为 ``None``）；results 为 spf / dkim /
    dmarc 的结果词列表，按原文顺序保留，重复声明不去重。
    """
    segments = value.split(";")
    first = segments[0].strip()
    authserv_id: str | None = None
    method_segments = segments[1:]
    if first:
        if "=" in first:
            # 首段本身就是方法声明：该字段没有 authserv-id
            method_segments = segments
        else:
            tokens = first.split()
            if tokens and tokens[0].lower() != "none":
                authserv_id = tokens[0]

    results: list[dict] = []
    for segment in method_segments:
        m = _METHOD_RESULT_RE.match(segment.strip())
        if not m:
            continue
        method = m.group(1).lower()
        if method in _TRACKED_METHODS:
            results.append({"method": method, "result": m.group(2)})
    return authserv_id, results


def _attribute(
    authserv_id: str | None, hop: dict | None
) -> tuple[str, str]:
    """根据对应跳的可信状态与身份核对结果给出归属结论与说明。"""
    if hop is None:
        return (
            ATTR_NO_HOP,
            "该字段之后（书写顺序向下）没有任何 Received，"
            "找不到写下它的接收跳",
        )
    top = hop["top_index"]
    by = hop.get("by_host")
    if not hop["trusted"]:
        if hop.get("is_boundary"):
            return (
                ATTR_BEYOND_BOUNDARY,
                f"对应跳为头部第 {top} 跳（by {by or '（缺失）'}），"
                "即可信边界（首个未命中名单的跳），该声明不受信任",
            )
        return (
            ATTR_BEYOND_BOUNDARY,
            f"对应跳为头部第 {top} 跳（by {by or '（缺失）'}），"
            "位于可信边界之外，该声明不受信任",
        )
    auth_norm = normalize_host(authserv_id)
    if auth_norm is None:
        return (
            ATTR_IDENTITY_MISMATCH,
            f"对应跳为头部第 {top} 跳（by {by}，可信），"
            "但该字段缺少 authserv-id，无法核对身份",
        )
    if auth_norm != normalize_host(by):
        return (
            ATTR_IDENTITY_MISMATCH,
            f"对应跳为头部第 {top} 跳（by {by}，可信），"
            f"但 authserv-id（{authserv_id}）与该跳 by 主机不一致",
        )
    return (
        ATTR_ORG_CLAIM,
        f"authserv-id 与头部第 {top} 跳（可信前缀内）的 by 主机一致，"
        "属本组织声明",
    )


def analyze_auth_results(
    raw_headers: str, trusted_hosts: str | list[str] | tuple[str, ...]
) -> dict:
    """把每条 Authentication-Results 归属到接收跳并判定是否为本组织声明。

    返回页面与 ``POST /api/analyze/auth-results`` 共用的结构化结果；
    名单为空或类型错误时返回 ``{"error": ...}``（调用方据此回 400）。
    顶端未命中名单（``untrusted_top``）与没有 Received（``no_received``）
    属于正常分析结果：``status`` 为 ``none``，明确表示无本组织声明。
    """
    trust = analyze_trust_boundary(raw_headers, trusted_hosts)
    if "error" in trust:
        return {"error": trust["error"]}

    blocks = parse_header_blocks(raw_headers)
    received_blocks = [
        b for b in blocks if b.name.lower() == RECEIVED_FIELD_NAME
    ]
    ar_blocks = [b for b in blocks if b.name.lower() == AR_FIELD_NAME]
    received_orders = [b.order for b in received_blocks]
    # trust["hops"] 与 received_blocks 同为头部书写顺序，按下标一一对应
    trust_hops = trust["hops"]

    fields: list[dict] = []
    for ar_index, block in enumerate(ar_blocks, start=1):
        authserv_id, results = _parse_ar_value(block.value)
        # 其后紧邻的 Received：书写顺序中它之后的第一条 Received
        hop_idx = bisect.bisect_right(received_orders, block.order)
        hop = trust_hops[hop_idx] if hop_idx < len(trust_hops) else None

        attribution, detail = _attribute(authserv_id, hop)
        fields.append(
            {
                "ar_index": ar_index,
                "field_position": block.order + 1,
                "authserv_id": authserv_id,
                "attribution": attribution,
                "attribution_label": _ATTR_LABELS[attribution],
                "detail": detail,
                "hop_top_index": hop["top_index"] if hop else None,
                "hop_by": hop.get("by_host") if hop else None,
                "hop_trusted": hop["trusted"] if hop else None,
                # 结果词只对本组织声明提取，其余字段保持空数组
                "results": results if attribution == ATTR_ORG_CLAIM else [],
                "raw": block.raw,
            }
        )

    claims = [f for f in fields if f["attribution"] == ATTR_ORG_CLAIM]
    ar_total = len(fields)
    trust_status = trust["status"]
    trusted_count = trust["trusted_count"]

    if trust_status == STATUS_NO_RECEIVED:
        message = "头部中未找到 Received 字段，无法建立可信前缀：无本组织声明。"
        if ar_total:
            message += f"{ar_total} 条 Authentication-Results 均无对应跳。"
    elif trust_status == STATUS_UNTRUSTED_TOP:
        message = (
            "无法从顶端建立可信前缀（顶端第 1 跳未命中本组织名单或缺少 by）："
            "无本组织声明。"
        )
        if ar_total:
            message += f"{ar_total} 条 Authentication-Results 均不可信。"
    elif ar_total == 0:
        message = (
            f"已建立自顶端连续 {trusted_count} 跳的可信前缀，"
            "但头部中没有 Authentication-Results 字段：无本组织声明。"
        )
    elif not claims:
        message = (
            f"已建立自顶端连续 {trusted_count} 跳的可信前缀，但 "
            f"{ar_total} 条 Authentication-Results 均不满足归属条件"
            "（无对应跳 / 越过边界 / 身份不符）：无本组织声明。"
        )
    elif len(claims) == ar_total:
        message = (
            f"自顶端连续 {trusted_count} 跳可信前缀内，全部 {ar_total} 条 "
            "Authentication-Results 均归属为本组织声明。"
        )
    else:
        message = (
            f"自顶端连续 {trusted_count} 跳可信前缀内，{ar_total} 条 "
            f"Authentication-Results 中有 {len(claims)} 条归属为本组织声明，"
            f"其余 {ar_total - len(claims)} 条不满足归属条件。"
        )

    status = STATUS_FOUND if claims else STATUS_NONE
    return {
        "status": status,
        "status_label": _STATUS_LABELS[status],
        "message": message,
        "trusted_hosts": trust["trusted_hosts"],
        "hop_count": trust["hop_count"],
        "trusted_count": trusted_count,
        "trust_status": trust_status,
        "trust_status_label": trust["status_label"],
        "boundary": trust["boundary"],
        "ar_total": ar_total,
        "org_claim_count": len(claims),
        "claims": claims,
        "fields": fields,
    }
