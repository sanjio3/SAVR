package com.rasp.probe;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class RaspSemanticEngine {
    private static final Pattern OBVIOUS_ATTACK = Pattern.compile(
            "(?i)(union\\s+select|or\\s+1=1|jndi:|ldap://|rmi://|dns://|runtime\\.|processbuilder|/etc/passwd|"
                    + "\\.\\./\\.\\.|\\.\\.\\\\|cmd\\.exe|powershell|<script|javascript:|onerror\\s*=|onload\\s*=|"
                    + "invokertransformer|templatesimpl|instantiatetransformer|com\\.sun\\.rowset|jdk\\.nashorn|"
                    + "clojure\\.|ysoserial|169\\.254\\.169\\.254|metadata\\.google|/latest/meta-data|"
                    // M2 盲点：反序列化 gadget / SSTI 执行工具类是无条件攻击签名
                    + "signedobject|jndiobjectfactorybean|propertypathfactorybean|com\\.mchange\\.v2\\.c3p0|"
                    + "freemarker\\.template\\.utility\\.execute|javax\\.script\\.scriptenginemanager|"
                    + "(@type|_class|javaclass)\\s*['\\\"]?\\s*[:=]\\s*['\\\"]?"
                    + "(com\\.sun\\.|org\\.apache\\.commons\\.|javax\\.script|jdk\\.nashorn|com\\.mchange|"
                    + "org\\.springframework\\.|java\\.net\\.inet))");

    /**
     * 家族签名，仅在「污点已确认」时参与判定 (isDangerousContent)，绝不进入 L1 全 payload 扫描
     * (inspectUnsafe)。原因：这些片段在**应用自己**构造的查询/模板里是合法的（例如后端主动写
     * 的 Mongo 查询文档天然含 {@code $ne}、Freemarker 视图天然含 {@code <#if>}），只有当它们
     * 出现在**攻击者可控的值**里才是注入。放进 L1 会大面积误拦，故按「污点 + 内容」双条件分治
     *。
     */
    private static final Pattern TAINT_ONLY_ATTACK = Pattern.compile(
            "(?i)("
                    // NoSQL 注入：操作符走私
                    + "\\$where|\\$regex|\\$ne\\s*[:=]|\\$gt\\s*[:=]|\\$lt\\s*[:=]|\\$or\\s*[:=]|\\$in\\s*[:=]|"
                    + "\\$expr|\\$function|\\$accumulator|sleep\\s*\\(\\s*\\d|this\\.password|"
                    // SSTI：模板指令 / 表达式逃逸
                    + "<#(assign|list|if|include|import|macro)|\\$\\{[^}]*(class|getruntime|exec|processbuilder|"
                    + "classloader|getclass|new\\s)|#set\\s*\\(|#\\{[^}]*(class|exec|runtime)|"
                    + "t\\s*\\(\\s*java\\.|\\.class\\.classloader|getclass\\(\\)\\.forname|"
                    // 多态反序列化：类型键走私
                    + "@type|_class\\s*[:=]|javaclass\\s*[:=]|!!(javax|com\\.sun|org\\.apache|java)\\.|"
                    + "rome\\.|resin\\.|bytecodes"
                    + ")");
    // 变形绕过归一化：去 SQL 块注释 /* ... */、行注释 -- ...、折叠连续空白，使 or/**/1=1、
    // union/**/select、or\n1=1 等变体在归一化后仍能被 OBVIOUS_ATTACK 命中。
    private static final Pattern SQL_BLOCK_COMMENT = Pattern.compile("/\\*.*?\\*/");
    private static final Pattern SQL_LINE_COMMENT = Pattern.compile("--[^\\n]*");
    private static final Pattern WHITESPACE_RUN = Pattern.compile("\\s+");

    private final EventBuffer eventBuffer;
    private final ProbeState state;

    public RaspSemanticEngine(EventBuffer eventBuffer, ProbeState state) {
        this.eventBuffer = eventBuffer;
        this.state = state;
    }

    public RaspDecision inspect(String sink, String payload) {
        return FailOpenDecision.run(() -> inspectUnsafe(sink, payload), RaspDecision.allow("fail-open"));
    }

    /**
     * Pure predicate — no event emission. True when the value carries an obvious attack
     * signature (OBVIOUS_ATTACK) or matches a BLOCKING rule. Used by the L2 taint gate to
     * avoid over-blocking benign (tainted but safe) values such as {@code id=1}, while
     * still blocking tainted values whose content is actually malicious ("污点确认攻击者可控 + 内容确认确为攻击" 才拦截).
     */
    public boolean isDangerousContent(String value) {
        if (value == null) {
            return false;
        }
        for (AgentRule rule : state.raspRules()) {
            if ("BLOCKING".equals(rule.state()) && matchesRule(rule, value)) {
                return true;
            }
        }
        if (OBVIOUS_ATTACK.matcher(value).find()) {
            return true;
        }
        // 家族签名 (NoSQL 操作符 / SSTI 指令 / 多态类型键)：仅污点值走此判定，见 TAINT_ONLY_ATTACK。
        if (TAINT_ONLY_ATTACK.matcher(value).find()) {
            return true;
        }
        // 变形绕过：归一化后复检，识别 or/**/1=1、union/**/select、
        // or\n1=1 等 L1 正则漏掉的注释/空白变体。仅在「污点已命中」时走此路径，故不引入额外误拦。
        String normalized = normalize(value);
        return OBVIOUS_ATTACK.matcher(normalized).find() || TAINT_ONLY_ATTACK.matcher(normalized).find();
    }

    private static String normalize(String value) {
        String s = SQL_BLOCK_COMMENT.matcher(value).replaceAll(" ");
        s = SQL_LINE_COMMENT.matcher(s).replaceAll(" ");
        return WHITESPACE_RUN.matcher(s).replaceAll(" ").trim();
    }

    public void reportCve(String cveId, String description, String poc) {
        eventBuffer.offer(new SecurityEvent(
                "CVE_REPORT",
                "HIGH",
                UUID.randomUUID().toString(),
                TaintStore.currentRequestId(),
                "CVE",
                poc == null ? description : poc,
                Map.of("cveId", cveId, "description", description == null ? "" : description, "mode", state.mode().name()),
                "", ""));
    }

    private RaspDecision inspectUnsafe(String sink, String payload) {
        String value = payload == null ? "" : payload;
        if (state.mode() != ProbeMode.BLOCK) {
            return RaspDecision.allow("not-block-mode");
        }
        for (AgentRule rule : state.raspRules()) {
            if (matchesRule(rule, value)) {
                eventBuffer.offer(event("RASP_RULE_MATCH", "HIGH", sink, value,
                        "rule-" + rule.id() + "-" + rule.state()));
                if ("BLOCKING".equals(rule.state())) {
                    return RaspDecision.block("matched-rule-" + rule.id());
                }
                return RaspDecision.allow("observed-rule-" + rule.id());
            }
        }
        if (OBVIOUS_ATTACK.matcher(value).find()) {
            eventBuffer.offer(event("RASP_BLOCKED_PAYLOAD", "HIGH", sink, value, "local-rule"));
            return RaspDecision.block("matched-local-rasp-rule");
        }
        if (looksEncodedOrReflective(value)) {
            eventBuffer.offer(event("RASP_SEMANTIC_REVIEW", "HIGH", sink, value, "ai-semantic-review"));
            return RaspDecision.allow("sent-to-ai-observation");
        }
        return RaspDecision.allow("benign");
    }

    private SecurityEvent event(String type, String severity, String sink, String payload, String reason) {
        java.util.Map<String, Object> ctx = new java.util.HashMap<>();
        ctx.put("mode", state.mode().name());
        ctx.put("reason", reason);
        ctx.put("decodedPreview", decodePreview(payload));
        return new SecurityEvent(
                type,
                severity,
                UUID.randomUUID().toString(),
                TaintStore.currentRequestId(),
                sink,
                payload,
                ctx,
                "", "");
    }

    private boolean looksEncodedOrReflective(String payload) {
        String lower = payload.toLowerCase(Locale.ROOT);
        if (lower.contains("class.forname") || lower.contains("getmethod") || lower.contains("invoke(")) {
            return true;
        }
        String compact = payload.replaceAll("\\s+", "");
        return compact.length() >= 24 && compact.matches("[A-Za-z0-9+/=]+") && decodePreview(compact).length() > 0;
    }

    private boolean matchesRule(AgentRule rule, String payload) {
        if (rule.pattern() == null || rule.pattern().isBlank()) {
            return false;
        }
        try {
            return Pattern.compile(rule.pattern()).matcher(payload).find();
        } catch (PatternSyntaxException ignored) {
            return payload.contains(rule.pattern());
        }
    }

    private String decodePreview(String payload) {
        try {
            byte[] decoded = Base64.getDecoder().decode(payload.replaceAll("\\s+", ""));
            String preview = new String(decoded, StandardCharsets.UTF_8);
            return preview.length() > 160 ? preview.substring(0, 160) : preview;
        } catch (RuntimeException ignored) {
            return "";
        }
    }
}
