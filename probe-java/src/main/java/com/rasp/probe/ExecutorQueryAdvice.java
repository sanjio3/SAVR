package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * BOLA / IDOR object-read collection that works for BOTH MyBatis access patterns:
 * <ul>
 *   <li>mapper interfaces (proxied via MapperProxy), and</li>
 *   <li>the native SqlSession / Executor path used by {@code SqlSessionFactoryBean}
 * </ul>
 * Every read funnels through {@code Executor.query}, so hooking it captures the
 * accessed domain object from the {@code MappedStatement} id
 * (e.g. {@code com.sanjio.mall.mapper.AddressMapper.findById}) and the first
 * parameter. The read is reported to {@link HookRuntime#reportObjectRead(String)},
 * feeding {@code SemanticContext.recordObjectAccess} so the semantic layer can flag a
 * BOLA suspect when the object was loaded without an ownership-level authorization.
 */
public final class ExecutorQueryAdvice {

    private ExecutorQueryAdvice() {
    }

    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void onEnter(@Advice.Argument(0) Object mappedStatement,
                               @Advice.Argument(1) Object parameter) {
        try {
            if (mappedStatement == null) {
                return;
            }
            // MappedStatement.getId -> "com.sanjio.mall.mapper.AddressMapper.findById"
            String stmtId = String.valueOf(mappedStatement.getClass()
                    .getMethod("getId").invoke(mappedStatement));
            String method = methodOf(stmtId);
            // 精度闸门：只把「按主键/唯一键定位到单个对象」的查询算作 BOLA 相关对象访问。
            // 无参或集合类查询（findAll / list / search）没有对象身份，若也记为对象访问，
            // 会让每次页面渲染都被判成 BOLA 盲点（实测 ProductMapper.findAll 产生全量噪声，
            // 且会让 D2 拿假证据"确认"越权候选——比不确认更糟）。
            if (!isSingleObjectLookup(method)) {
                return;
            }
            String entity = entityFromStatement(stmtId);
            Object id = parameter;
            // MyBatis @Param 会把参数包成 ParamMap（如 {id=1, param1=1}）。抽取真实 id 值，
            // 否则资源键会变成整串 map，BOLA 证据可读性很差。
            if (id instanceof java.util.Map<?, ?>) {
                java.util.Map<?, ?> map = (java.util.Map<?, ?>) id;
                Object picked = null;
                for (String key : new String[]{"id", "param1", "userId", "orderId",
                        "orderNo", "code", "username", "uid"}) {
                    Object v = map.get(key);
                    if (v != null) {
                        picked = v;
                        break;
                    }
                }
                if (picked == null && map.size() == 1) {
                    picked = map.values().iterator().next();
                }
                if (picked != null) {
                    id = picked;
                }
            }
            String resourceKey = entity + ":" + (id == null ? "?" : id);
            AgentLogger.info("bola", "executor-read stmt=" + stmtId + " key=" + resourceKey);
            HookRuntime.reportObjectRead(resourceKey);
        } catch (Throwable t) {
            // fail-open
            AgentLogger.warn("bola", "executor-read failed: " + t);
        }
    }

    // 取 MappedStatement id 最后一段 = Mapper 方法名，如 findById / findByCode。
    public static String methodOf(String stmtId) {
        if (stmtId == null) {
            return "";
        }
        String[] parts = stmtId.split("\\.");
        return parts.length == 0 ? stmtId : parts[parts.length - 1];
    }

    // 精度闸门：仅把「按主键或对象自身唯一业务键定位到单个对象」的查询记为 BOLA 相关对象访问。
    // 必须是 public（同 entityFromStatement 的 ByteBuddy 内联陷阱）。
    public static boolean isSingleObjectLookup(String method) {
        if (method == null || method.isEmpty()) {
            return false;
        }
        String m = method.trim();
        String lower = m.toLowerCase();
        // 1) 按主键定位单对象（最典型 BOLA 入口）：findById / selectById / getById / loadById / queryById
        if (lower.endsWith("byid") || lower.endsWith("byprimarykey")) {
            return true;
        }
        // 2) 按「对象自身唯一业务键」定位单对象：findByCode / findByOrderNo / findByUsername ...
        //    这些是 1:1 唯一键查询，命中即代表加载了某个具体对象，对 BOLA 检测有意义。
        //    明确排除 findByUserId / findByProduct 等「按外键取父级下属集合」的 1:N 查询
        //    （它们返回 List，没有单一对象身份，记成对象访问会产生全量噪声，如 product:?）。
        if (lower.matches("^(find|get|select|load|query)by(code|orderno|username|name|email|phone|token)$")) {
            return true;
        }
        //    如 deleteComment(id) / getOrder(1) / findUser(uid) / loadAddress(aid) / updateComment(cid)）。
        //    仅当名词不以 s / list / all / page 结尾，避免误收 findComments / findAll / selectList
        //    等返回集合的 1:N 查询（否则会像 ProductMapper.findAll 那样产生全量噪声）。
        //    纯语法启发式、不依赖运行时参数类型，杜绝 ByteBuddy 内联 fail-open 风险。
        if (lower.matches("^(delete|remove|update|get|find|load|select|query)[a-z]+$")
                && !lower.endsWith("s")
                && !lower.endsWith("list")
                && !lower.endsWith("all")
                && !lower.endsWith("page")
                && !lower.endsWith("by")) {
            return true;
        }
        return false;
    }

    // 必须是 public：ByteBuddy 会把 advice 代码内联进被织入的类（这里是 CachingExecutor /
    // BaseExecutor），private 成员会导致目标类访问时报 IllegalAccessError，并被 fail-open 静默吞掉。
    public static String entityFromStatement(String stmtId) {
        // last two segments: ...mapper.<Entity>Mapper.<method>
        String[] parts = stmtId.split("\\.");
        if (parts.length >= 2) {
            String mapper = parts[parts.length - 2]; // e.g. AddressMapper
            if (mapper.endsWith("Mapper")) {
                return mapper.substring(0, mapper.length() - "Mapper".length());
            }
            return mapper;
        }
        return "Unknown";
    }
}
