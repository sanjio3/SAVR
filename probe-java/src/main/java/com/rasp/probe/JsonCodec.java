package com.rasp.probe;

import java.util.Collection;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class JsonCodec {
    private JsonCodec() {
    }

    public static String stringify(Object value) {
        if (value == null) {
            return "null";
        }
        if (value instanceof String) {
            return quote((String) value);
        }
        if (value instanceof Number || value instanceof Boolean) {
            return value.toString();
        }
        if (value instanceof Map<?, ?>) {
            Map<?, ?> map = (Map<?, ?>) value;
            StringBuilder builder = new StringBuilder("{");
            boolean first = true;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (!first) {
                    builder.append(',');
                }
                first = false;
                builder.append(quote(String.valueOf(entry.getKey()))).append(':').append(stringify(entry.getValue()));
            }
            return builder.append('}').toString();
        }
        if (value instanceof Collection<?>) {
            Collection<?> collection = (Collection<?>) value;
            StringBuilder builder = new StringBuilder("[");
            boolean first = true;
            for (Object item : collection) {
                if (!first) {
                    builder.append(',');
                }
                first = false;
                builder.append(stringify(item));
            }
            return builder.append(']').toString();
        }
        return quote(value.toString());
    }

    public static Map<String, Object> parseFlatEnvelope(String json) {
        Map<String, Object> envelope = new LinkedHashMap<>();
        String data = extractObject(json, "data");
        if (data != null) {
            envelope.put("data", parseAgentConfig(data));
        }
        return envelope;
    }

    public static Map<String, Object> parseAgentConfig(String json) {
        Map<String, Object> config = new LinkedHashMap<>();
        String mode = extractString(json, "mode");
        if (mode != null) {
            config.put("mode", mode);
        }
        Long ruleVersion = extractLong(json, "ruleVersion");
        if (ruleVersion != null) {
            config.put("ruleVersion", ruleVersion);
        }
        config.put("rules", parseRules(json));
        return config;
    }

    public static List<AgentRule> parseRules(String json) {
        String rulesArray = extractArray(json, "rules");
        if (rulesArray == null || rulesArray.length() < 2) {
            return List.of();
        }
        List<AgentRule> rules = new ArrayList<>();
        for (String object : splitObjects(rulesArray)) {
            Long id = extractLong(object, "id");
            String type = extractString(object, "type");
            String state = extractString(object, "state");
            String pattern = extractString(object, "pattern");
            String targetClass = extractString(object, "targetClass");
            String targetMethod = extractString(object, "targetMethod");
            Double confidence = extractDouble(object, "confidence");
            String description = extractString(object, "description");
            if (id != null && type != null && state != null) {
                rules.add(new AgentRule(id, type, state, pattern, targetClass, targetMethod,
                        confidence == null ? 0 : confidence, description));
            }
        }
        return rules;
    }

    private static String quote(String value) {
        // 2026-10-15 修复（P-A 根因）：原实现只转义 \\ " \n，**漏了 \r \t 及其它控制字符**。
        // 事件体里任一字段（栈帧的 Windows \r\n、payload/taint_path 里的 \t 等）含未转义控制字符，
        // 就会让整批 JSON 非法 → 后端 _safe_json 解析失败 → events=[] → accepted:0（HTTP 200），
        // 整批事件被**静默丢弃**且探针侧无告警。实测：含裸 \r 或 \t 的 body → accepted:0 不落库。
        // 这正是「带 canary 的 sink 事件到不了 iast_events、而纯噪声批次能落」的根因。
        // 现按 RFC 8259 完整转义：所有 < 0x20 的控制字符走 unicode 转义（U+XXXX 形式）。
        StringBuilder sb = new StringBuilder(value.length() + 2);
        sb.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                default:
                    if (c < 0x20) {
                        // 用 char 拼接产出 U+XXXX 转义形式；避免源码里出现裸的 unicode 转义前缀
                        // （javac 会在词法分析前处理它，字面量里出现会被误判为非法转义）。
                        sb.append('\\').append('u').append(String.format("%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
        return sb.toString();
    }

    private static String extractString(String json, String field) {
        String token = "\"" + field + "\"";
        int start = json.indexOf(token);
        if (start < 0) {
            return null;
        }
        int colon = json.indexOf(':', start);
        int firstQuote = json.indexOf('"', colon + 1);
        int secondQuote = json.indexOf('"', firstQuote + 1);
        if (colon < 0 || firstQuote < 0 || secondQuote < 0) {
            return null;
        }
        return json.substring(firstQuote + 1, secondQuote);
    }

    private static Long extractLong(String json, String field) {
        String token = "\"" + field + "\"";
        int start = json.indexOf(token);
        if (start < 0) {
            return null;
        }
        int colon = json.indexOf(':', start);
        if (colon < 0) {
            return null;
        }
        int index = colon + 1;
        while (index < json.length() && Character.isWhitespace(json.charAt(index))) {
            index++;
        }
        int end = index;
        while (end < json.length() && Character.isDigit(json.charAt(end))) {
            end++;
        }
        if (end == index) {
            return null;
        }
        return Long.parseLong(json.substring(index, end));
    }

    private static Double extractDouble(String json, String field) {
        String token = "\"" + field + "\"";
        int start = json.indexOf(token);
        if (start < 0) {
            return null;
        }
        int colon = json.indexOf(':', start);
        if (colon < 0) {
            return null;
        }
        int index = colon + 1;
        while (index < json.length() && Character.isWhitespace(json.charAt(index))) {
            index++;
        }
        int end = index;
        while (end < json.length() && (Character.isDigit(json.charAt(end)) || json.charAt(end) == '.')) {
            end++;
        }
        if (end == index) {
            return null;
        }
        return Double.parseDouble(json.substring(index, end));
    }

    private static String extractObject(String json, String field) {
        String token = "\"" + field + "\"";
        int start = json.indexOf(token);
        if (start < 0) {
            return null;
        }
        int objectStart = json.indexOf('{', start);
        if (objectStart < 0) {
            return null;
        }
        int depth = 0;
        for (int index = objectStart; index < json.length(); index++) {
            char current = json.charAt(index);
            if (current == '{') {
                depth++;
            } else if (current == '}') {
                depth--;
                if (depth == 0) {
                    return json.substring(objectStart, index + 1);
                }
            }
        }
        return null;
    }

    private static String extractArray(String json, String field) {
        String token = "\"" + field + "\"";
        int start = json.indexOf(token);
        if (start < 0) {
            return null;
        }
        int arrayStart = json.indexOf('[', start);
        if (arrayStart < 0) {
            return null;
        }
        int depth = 0;
        boolean inString = false;
        for (int index = arrayStart; index < json.length(); index++) {
            char current = json.charAt(index);
            if (current == '"' && (index == 0 || json.charAt(index - 1) != '\\')) {
                inString = !inString;
            }
            if (inString) {
                continue;
            }
            if (current == '[') {
                depth++;
            } else if (current == ']') {
                depth--;
                if (depth == 0) {
                    return json.substring(arrayStart, index + 1);
                }
            }
        }
        return null;
    }

    private static List<String> splitObjects(String arrayJson) {
        List<String> objects = new ArrayList<>();
        int depth = 0;
        int objectStart = -1;
        boolean inString = false;
        for (int index = 0; index < arrayJson.length(); index++) {
            char current = arrayJson.charAt(index);
            if (current == '"' && (index == 0 || arrayJson.charAt(index - 1) != '\\')) {
                inString = !inString;
            }
            if (inString) {
                continue;
            }
            if (current == '{') {
                if (depth == 0) {
                    objectStart = index;
                }
                depth++;
            } else if (current == '}') {
                depth--;
                if (depth == 0 && objectStart >= 0) {
                    objects.add(arrayJson.substring(objectStart, index + 1));
                    objectStart = -1;
                }
            }
        }
        return objects;
    }
}
