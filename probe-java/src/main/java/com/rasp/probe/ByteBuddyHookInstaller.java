package com.rasp.probe;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.ClassFileLocator;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.dynamic.loading.ClassInjector;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.utility.JavaModule;

import java.io.File;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.util.Map;

import static net.bytebuddy.matcher.ElementMatchers.hasSuperType;
import static net.bytebuddy.matcher.ElementMatchers.isAbstract;
import static net.bytebuddy.matcher.ElementMatchers.isConstructor;
import static net.bytebuddy.matcher.ElementMatchers.isInterface;
import static net.bytebuddy.matcher.ElementMatchers.isMethod;
import static net.bytebuddy.matcher.ElementMatchers.isNative;
import static net.bytebuddy.matcher.ElementMatchers.isSynthetic;
import static net.bytebuddy.matcher.ElementMatchers.nameContains;
import static net.bytebuddy.matcher.ElementMatchers.nameStartsWith;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.namedOneOf;
import static net.bytebuddy.matcher.ElementMatchers.none;
import static net.bytebuddy.matcher.ElementMatchers.not;
import static net.bytebuddy.matcher.ElementMatchers.returns;
import static net.bytebuddy.matcher.ElementMatchers.takesArgument;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

public final class ByteBuddyHookInstaller {
    private ByteBuddyHookInstaller() {
    }

    public static void install(Instrumentation instrumentation, ProbeConfig config) {
        FailOpen.run("bytebuddy-install", () -> {
            AgentLogger.info("hook", "installing ByteBuddy hooks");
            File bootstrapDir = bootstrapDir();
            injectBootstrapHelpers(instrumentation, bootstrapDir);
            if (config.servletHooksEnabled()) {
                installServletHooks(instrumentation);
                installTrustBoundHooks(instrumentation);
            }
            if (config.jdbcHooksEnabled()) {
                installJdbcHooks(instrumentation);
                installOrmHooks(instrumentation);
            }
            if (config.commandHooksEnabled()) {
                installCommandHooks(instrumentation, bootstrapDir);
            }
            if (config.expressionHooksEnabled()) {
                installExpressionHooks(instrumentation);
                installXPathHooks(instrumentation, bootstrapDir);
            }
            if (config.deserializationHooksEnabled()) {
                installDeserializationHooks(instrumentation, bootstrapDir);
                installXmlHooks(instrumentation, bootstrapDir);
                installXStreamHooks(instrumentation);
            }
            if (config.fileHooksEnabled()) {
                installFileHooks(instrumentation, bootstrapDir);
            }
            if (config.httpClientHooksEnabled()) {
                installHttpClientHooks(instrumentation, bootstrapDir);
            }
            if (config.jndiHooksEnabled()) {
                installJndiHooks(instrumentation, bootstrapDir);
                installLog4jHooks(instrumentation);
            }
            if (config.servletHooksEnabled()) {
                installXssResponseHooks(instrumentation);
                installResponseRedirectHooks(instrumentation);
                installXssServletOutputHooks(instrumentation, bootstrapDir);
                // Phase1 根因修复（2026-10-11）：PrintWriter bootstrap hook 被 CoyoteWriter
                // 子类 override 绕过（javap 证实其重写了全部 write/print/println），
                // 必须直钩 Tomcat 的 CoyoteWriter 才能观测裸 servlet 响应体写入。
                installCoyoteWriterHooks(instrumentation);
            }
            if (config.propagatorHooksEnabled()) {
                installPropagatorHooks(instrumentation, bootstrapDir);
                installBoundaryHooks(instrumentation, bootstrapDir);
                installReflectionSinkHooks(instrumentation, bootstrapDir);
            }
            // M2 盲点 sink 家族 (手册 11.4.1 / 11.4.2): Jackson 多态反序列化、NoSQL(Mongo)
            // 注入、SSTI 模板引擎、GraphQL。全部是应用类加载器类型，走默认注入策略。
            if (config.blindSpotHooksEnabled()) {
                installBlindSpotSinkHooks(instrumentation, bootstrapDir);
            }
            // 字段级污点边 (11.1.3 十.1) 与数组重组继承 (11.1.3 十.5)。java.lang.reflect.Field /
            // java.util.Arrays 都在 java.base，必须 bootstrap 注入。
            if (config.fieldTaintHooksEnabled()) {
                installFieldTaintHooks(instrumentation, bootstrapDir);
            }
            if (config.arrayTaintHooksEnabled()) {
                installArrayTaintHooks(instrumentation, bootstrapDir);
            }
            if (config.asyncContextEnabled()) {
                installAsyncContextHooks(instrumentation, bootstrapDir);
            }
            if (config.frameworkHooksEnabled()) {
                installFrameworkHooks(instrumentation);
            }
            // Semantic (policy) RASP layer. Repository reads feed both BOLA
            // correlation and the race detector, so they are installed whenever
            // either category is enabled.
            if (config.authzHooksEnabled() || config.raceHooksEnabled()) {
                installRepositoryReadHooks(instrumentation);
            }
            if (config.authzHooksEnabled()) {
                installAuthzDecisionHooks(instrumentation);
            }
            if (config.raceHooksEnabled()) {
                installRepositoryWriteHooks(instrumentation);
                installConcurrencyHooks(instrumentation);
            }
        });
    }

    /**
     * 包内可见：{@link VirtualPatchEngine} 复用同一份 ignore 列表与安装监听器，保证方法级
     * 虚拟补丁与常规 Hook Pack 走完全一致的织入边界 (绝不 retransform 探针自身)。
     */
    static AgentBuilder baseBuilder() {
        return new AgentBuilder.Default()
                .ignore(nameStartsWith("net.bytebuddy.")
                        .or(nameStartsWith("com.rasp.probe."))
                        .or(nameStartsWith("org.junit."))
                        .or(nameStartsWith("org.mockito."))
                        .or(isSynthetic()))
                .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
                .with(AgentBuilder.InjectionStrategy.UsingUnsafe.INSTANCE)
                .with(new HookInstallListener());
    }

    private static AgentBuilder bootstrapBuilder(Instrumentation instrumentation, File bootstrapDir) {
        return baseBuilder()
                .with(new AgentBuilder.InjectionStrategy.UsingInstrumentation(instrumentation, bootstrapDir));
    }

    private static void installServletHooks(Instrumentation instrumentation) {
        baseBuilder()
                .type(hasSuperType(named("javax.servlet.ServletRequest"))
                        .or(hasSuperType(named("jakarta.servlet.ServletRequest"))))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(ServletGetParameterAdvice.class)
                                .on(named("getParameter").and(takesArguments(String.class))))
                        .visit(Advice.to(ServletGetParameterValuesAdvice.class)
                                .on(named("getParameterValues").and(takesArguments(String.class))))
                        .visit(Advice.to(ServletGetParameterMapAdvice.class)
                                .on(named("getParameterMap").and(takesArguments(0))))
                        .visit(Advice.to(ServletGetHeaderAdvice.class)
                                .on(named("getHeader").and(takesArguments(String.class))))
                        .visit(Advice.to(ServletGetCookiesAdvice.class)
                                .on(named("getCookies").and(takesArguments(0)))))
                .installOn(instrumentation);

        baseBuilder()
                .type(hasSuperType(named("javax.servlet.Servlet"))
                        .or(hasSuperType(named("jakarta.servlet.Servlet"))))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(ServletServiceAdvice.class)
                                .on(named("service").and(takesArguments(2)))))
                .installOn(instrumentation);
    }

    private static void installJdbcHooks(Instrumentation instrumentation) {
        baseBuilder()
                .type(hasSuperType(named("java.sql.Statement")))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(SqlSinkAdvice.class)
                                .on(namedOneOf("execute", "executeQuery", "executeUpdate", "executeLargeUpdate",
                                        "addBatch").and(takesArgument(0, String.class))))
                        // L3 语义层：同一 matcher 上再挂一个 exit advice 采集「抛没抛异常」。
                        // 用两个独立 .visit() 而非 Advice.with(...).advice(...)：后者在
                        // byte-buddy 1.15.11 不存在（with 方法无此重载），且本代码库既有
                        // 多 advice 模式（installResponseRedirectHooks）即为此写法。
                        .visit(Advice.to(SinkOutcomeAdvice.class)
                                .on(namedOneOf("execute", "executeQuery", "executeUpdate", "executeLargeUpdate",
                                        "addBatch").and(takesArgument(0, String.class)))))
                .installOn(instrumentation);

        // PreparedStatement：值级 sanitized 判据的关键场景（OWASP sqli 安全用例走这里）。
        // 挂 SinkOutcomeAdvice 的额外价值：绑定变量类型不匹配时 execute 会抛
        // SQLException/NumberFormatException，可据此判定「payload 未生效」。
        baseBuilder()
                .type(hasSuperType(named("java.sql.PreparedStatement")))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(PreparedSqlSinkAdvice.class)
                                .on(namedOneOf("execute", "executeQuery", "executeUpdate", "executeLargeUpdate",
                                        "addBatch").and(takesArguments(0))))
                        .visit(Advice.to(SinkOutcomeAdvice.class)
                                .on(namedOneOf("execute", "executeQuery", "executeUpdate", "executeLargeUpdate",
                                        "addBatch").and(takesArguments(0)))))
                .installOn(instrumentation);

        // 参数化查询感知 (手册 11.1.5 一): register the SQL template at prepare time and the
        // bound values at set time, so execution can tell a concatenated (injectable)
        // template apart from a static template that merely carries a tainted parameter.
        baseBuilder()
                .type(hasSuperType(named("java.sql.Connection")))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(PrepareStatementAdvice.class)
                                .on(namedOneOf("prepareStatement", "prepareCall")
                                        .and(takesArgument(0, String.class)))))
                .installOn(instrumentation);

        baseBuilder()
                .type(hasSuperType(named("java.sql.PreparedStatement")))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(PreparedParameterAdvice.class)
                                .on(namedOneOf("setString", "setNString", "setObject", "setBytes")
                                        .and(takesArguments(2))
                                        .and(takesArgument(0, int.class)))))
                .installOn(instrumentation);
    }

    private static void installOrmHooks(Instrumentation instrumentation) {
        baseBuilder()
                .type(hasSuperType(named("jakarta.persistence.EntityManager"))
                        .or(hasSuperType(named("javax.persistence.EntityManager")))
                        .or(hasSuperType(named("org.hibernate.Session"))))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(GenericSinkAdvice.class)
                                .on(namedOneOf("createQuery", "createNativeQuery", "createSQLQuery")
                                        .and(takesArgument(0, String.class))))
                        .visit(Advice.to(SinkOutcomeAdvice.class)
                                .on(namedOneOf("createQuery", "createNativeQuery", "createSQLQuery")
                                        .and(takesArgument(0, String.class)))))
                .installOn(instrumentation);

        baseBuilder()
                .type(hasSuperType(named("org.apache.ibatis.executor.Executor")))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(GenericSinkAdvice.class)
                                .on(namedOneOf("query", "update")))
                        .visit(Advice.to(SinkOutcomeAdvice.class)
                                .on(namedOneOf("query", "update"))))
                .installOn(instrumentation);
    }

    private static void installCommandHooks(Instrumentation instrumentation, File bootstrapDir) {
        bootstrapBuilder(instrumentation, bootstrapDir)
                .type(named("java.lang.Runtime"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(BootstrapGenericSinkAdvice.class)
                                .on(named("exec")))
                        .visit(Advice.to(SinkOutcomeAdvice.class)
                                .on(named("exec"))))
                .installOn(instrumentation);

        bootstrapBuilder(instrumentation, bootstrapDir)
                .type(named("java.lang.ProcessBuilder"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(BootstrapProcessBuilderStartAdvice.class)
                                .on(named("start").and(takesArguments(0)))))
                .installOn(instrumentation);
    }

    private static void installExpressionHooks(Instrumentation instrumentation) {
        baseBuilder()
                .type(named("org.springframework.expression.ExpressionParser")
                        .or(hasSuperType(named("org.springframework.expression.ExpressionParser"))))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(GenericSinkAdvice.class)
                                .on(named("parseExpression").and(takesArgument(0, String.class))))
                        .visit(Advice.to(SinkOutcomeAdvice.class)
                                .on(named("parseExpression").and(takesArgument(0, String.class)))))
                .installOn(instrumentation);

        baseBuilder()
                .type(nameStartsWith("ognl."))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(GenericSinkAdvice.class)
                                .on(namedOneOf("parseExpression", "getValue", "setValue")))
                        .visit(Advice.to(SinkOutcomeAdvice.class)
                                .on(namedOneOf("parseExpression", "getValue", "setValue"))))
                .installOn(instrumentation);
    }

    private static void installDeserializationHooks(Instrumentation instrumentation, File bootstrapDir) {
        // 方案 B 反序列化桥接：把「污点流经反序列化入口」作为 transform 跳点，供 I1 逐节点核对。
        // 关键坑（JDK24 实测）：java.io.ObjectInputStream.readObject() 是 final 方法，ByteBuddy 无法
        // 对其织入 advice（类会被「transformed」但 readObject 本体仍是原字节码，onEnter 永不触发）。
        // 故改为钩住非 final 的 resolveClass(ObjectStreamClass)——它在反序列化每个对象时必被调用，
        // 是「反序列化确实在发生」的可靠语义点；readObject 仅在成功反序列化路径上间接触发它。
        // 另：installOn(RETRANSFORMATION) 对该已加载核心类的自动重变换在某些启动时序下不可靠（偶发
        // 不织入），故显式 retransformClasses 一次以保证确定性织入。
        bootstrapBuilder(instrumentation, bootstrapDir)
                .type(named("java.io.ObjectInputStream"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(BootstrapGenericSinkAdvice.class)
                                .on(named("resolveClass").and(takesArguments(1))))
                        // 2026-09-28 第三层：构造器污点传播（流 → ObjectInputStream 实例）。
                        // 用独立 advice 类而非 BootstrapGenericSinkAdvice：后者会把构造器 origin
                        // 落进 onGenericSink，把反序列化错标成 sink，破坏 chain_conformance
                        // 的 transform 匹配（该节点本应是「污点流经的桥接点」）。
                        .visit(Advice.to(PropagateObjectStreamCtorAdvice.class).on(isConstructor())))
                .installOn(instrumentation);
        try {
            Class<?> ois = Class.forName("java.io.ObjectInputStream");
            if (instrumentation.isModifiableClass(ois)) {
                instrumentation.retransformClasses(ois);
            }
        } catch (Throwable ignored) {
            // fail-open：重变换失败不影响其余钩子
        }
    }

    // XXE / untrusted XML parsing sinks. DocumentBuilder.parse, SAXParser.parse,
    // XMLReader.parse and Transformer.transform all ingest attacker-controlled XML that
    // may carry external-entity / malicious-DTD payloads. There was previously NO hook
    // for any XML parser, so XXE could never be observed or blocked by RASP.
    // These JDK types live in the java.xml module, so we inject the bootstrap advice
    // (as with ObjectInputStream) keeping the relay through BootstrapBridge.
    // NOTE: every XML parser type here is an abstract class or interface; the runtime
    // instance is a JDK impl (e.g. com.sun.org.apache.xerces.internal.jaxp.DocumentBuilderImpl
    // extends DocumentBuilder; com.sun.org.apache.xerces.internal.parsers.SAXParser
    // implements XMLReader; ...TransformerImpl extends Transformer). We match with
    // hasSuperType(named("X")) — ByteBuddy's hasSuperType traverses BOTH the superclass
    // chain AND implemented interfaces, so it matches every concrete impl whether the
    // matched type is an abstract class or an interface (verified: hasSuperType(named(
    // "java.lang.Runnable")) matches a Runnable implementation).
    private static void installXmlHooks(Instrumentation instrumentation, File bootstrapDir) {
        bootstrapBuilder(instrumentation, bootstrapDir)
                .type(hasSuperType(named("javax.xml.parsers.DocumentBuilder")))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(BootstrapGenericSinkAdvice.class)
                                .on(named("parse"))))
                .installOn(instrumentation);

        bootstrapBuilder(instrumentation, bootstrapDir)
                .type(hasSuperType(named("org.xml.sax.XMLReader")))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(BootstrapGenericSinkAdvice.class)
                                .on(named("parse"))))
                .installOn(instrumentation);

        bootstrapBuilder(instrumentation, bootstrapDir)
                .type(hasSuperType(named("javax.xml.parsers.SAXParser")))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(BootstrapGenericSinkAdvice.class)
                                .on(named("parse"))))
                .installOn(instrumentation);

        bootstrapBuilder(instrumentation, bootstrapDir)
                .type(hasSuperType(named("javax.xml.transform.Transformer")))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(BootstrapGenericSinkAdvice.class)
                                .on(named("transform"))))
                .installOn(instrumentation);

        // XXE sink: dom4j。java-sec-code /xxe/DocumentHelper/vuln 经
        // org.dom4j.DocumentHelper.parseText 解析不可信 XML，不属于本方法覆盖的 JAXP
        // 层级（DocumentBuilder / XMLReader / SAXParser / Transformer），此前无插桩。
        // dom4j 是应用类加载器类型（fat jar 内依赖），故走默认注入策略。
        baseBuilder()
                .type(nameStartsWith("org.dom4j."))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(GenericSinkAdvice.class)
                                .on(namedOneOf("parseText", "read"))))
                .installOn(instrumentation);
    }

    private static void installFrameworkHooks(Instrumentation instrumentation) {
        installDubboHooks(instrumentation);
        installGrpcHooks(instrumentation);
        installRedisHooks(instrumentation);
        installEsHooks(instrumentation);
    }

    // Dubbo RPC: the Invoker.invoke call is the inbound command boundary (the Invocation
    // carries the serialized arguments), so it is a sink.
    private static void installDubboHooks(Instrumentation instrumentation) {
        baseBuilder()
                .type(hasSuperType(named("org.apache.dubbo.rpc.Invoker"))
                        .or(hasSuperType(named("com.alibaba.dubbo.rpc.Invoker"))))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(GenericSinkAdvice.class)
                                .on(named("invoke").and(
                                        takesArgument(0, named("org.apache.dubbo.rpc.Invocation"))
                                                .or(takesArgument(0, named("com.alibaba.dubbo.rpc.Invocation")))))))
                .installOn(instrumentation);
    }

    // gRPC: the Marshaller is the wire boundary. stream(Object) serializes the
    // outbound response (sink).
    private static void installGrpcHooks(Instrumentation instrumentation) {
        baseBuilder()
                .type(hasSuperType(named("io.grpc.MethodDescriptor$Marshaller")))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(GenericSinkAdvice.class)
                                .on(named("stream"))))
                .installOn(instrumentation);
    }

    // Redis: Spring Data RedisTemplate raw-command execution (execute/executePipelined/
    // executeSession) and Jedis script eval (Lua injection) are sinks.
    private static void installRedisHooks(Instrumentation instrumentation) {
        baseBuilder()
                .type(named("org.springframework.data.redis.core.RedisTemplate")
                        .or(named("org.springframework.data.redis.core.StringRedisTemplate")))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(GenericSinkAdvice.class)
                                .on(namedOneOf("execute", "executePipelined", "executeSession"))))
                .installOn(instrumentation);

        baseBuilder()
                .type(named("redis.clients.jedis.Jedis"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(GenericSinkAdvice.class)
                                .on(namedOneOf("eval", "evalSha", "evalRead", "evalWrite"))))
                .installOn(instrumentation);
    }

    // Elasticsearch: RestHighLevelClient query/index operations and the low-level
    // RestClient performRequest are sinks — the request object is the query/body payload.
    private static void installEsHooks(Instrumentation instrumentation) {
        baseBuilder()
                .type(named("org.elasticsearch.client.RestHighLevelClient"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(GenericSinkAdvice.class)
                                .on(namedOneOf("search", "msearch", "searchAsync", "index", "update", "delete",
                                        "bulk"))))
                .installOn(instrumentation);

        baseBuilder()
                .type(named("org.elasticsearch.client.RestClient"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(GenericSinkAdvice.class)
                                .on(namedOneOf("performRequest", "performRequestAsync"))))
                .installOn(instrumentation);
    }

    private static void installFileHooks(Instrumentation instrumentation, File bootstrapDir) {
        bootstrapBuilder(instrumentation, bootstrapDir)
                .type(named("java.io.FileInputStream")
                        .or(named("java.io.FileOutputStream"))
                        .or(named("java.io.RandomAccessFile")))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(BootstrapGenericSinkAdvice.class)
                                .on(isConstructor())))
                .installOn(instrumentation);

        bootstrapBuilder(instrumentation, bootstrapDir)
                .type(named("java.nio.file.Files"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(BootstrapGenericSinkAdvice.class)
                                .on(namedOneOf("newInputStream", "newOutputStream", "readString", "readAllLines",
                                        "readAllBytes", "write", "writeString", "delete", "deleteIfExists", "copy", "move",
                                        "lines"))))
                .installOn(instrumentation);
    }

    private static void installLog4jHooks(Instrumentation instrumentation) {
        baseBuilder()
                .type(nameStartsWith("org.apache.logging.log4j.core.lookup")
                        .or(nameStartsWith("org.apache.logging.log4j.core.net")))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(GenericSinkAdvice.class)
                                .on(namedOneOf("lookup", "resolve", "replace", "format"))))
                .installOn(instrumentation);
    }

    private static void installHttpClientHooks(Instrumentation instrumentation, File bootstrapDir) {
        installSsrfUrlConnectionHooks(instrumentation, bootstrapDir);

        // App-level HTTP client libraries (okhttp / apache / JDK java.net.http). These are
        // application-classloader types. NOTE: the JDK java.net.http.HttpClient is a
        // platform class and its advice (GenericSinkAdvice) lives in the agent class loader,
        // so it is matched here only for clients that resolve in the application loader;
        // matching the raw platform class would fail-open (see §十.3 limitation notes).
        baseBuilder()
                .type(hasSuperType(named("java.net.http.HttpClient"))
                        .or(nameStartsWith("org.apache.http.impl.client"))
                        // Apache HttpAsyncClient 的实现在 org.apache.http.impl.nio.client，
                        // 不是 org.apache.http.impl.client 的子包（末段是 nio 而非 client），
                        // 只写前者会整族漏插桩。java-sec-code /ssrf/HttpSyncClients/vuln 即走此路径：
                        // HttpAsyncClients.createDefault() -> CloseableHttpAsyncClient.execute()。
                        .or(nameStartsWith("org.apache.http.impl.nio.client"))
                        .or(nameStartsWith("okhttp3."))
                        // okhttp 2.x 的包名是 com.squareup.okhttp（无数字 3），4.x/3.x 才是 okhttp3。
                        // java-sec-code 依赖 okhttp 2.5.0，只写 okhttp3 会整族漏插桩。
                        .or(nameStartsWith("com.squareup.okhttp.")))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(GenericSinkAdvice.class)
                                .on(namedOneOf("send", "sendAsync", "execute", "newCall"))))
                .installOn(instrumentation);

        // SSRF sink: javax.imageio.ImageIO.read(...)。java-sec-code /ssrf/ImageIO/sec 经此
        // JDK API 发起请求，不落到 sun.net.www.protocol.http.HttpURLConnection 的
        // connect/getInputStream（探针此前无任何 imageio 插桩，该端点因此恒 no-arrival）。
        // ImageIO 属 java.desktop 模块，须走 bootstrap 注入策略。
        bootstrapBuilder(instrumentation, bootstrapDir)
                .type(named("javax.imageio.ImageIO"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(BootstrapGenericSinkAdvice.class)
                                .on(named("read"))))
                .installOn(instrumentation);
    }

    /**
     * SSRF sink: the concrete HTTP(S) {@code URLConnection}. Unlike {@code java.net.URL},
     * the http(s) protocol handler is exercised only by real outbound HTTP calls — not by
     * the file:/jar: connections the class loader opens during startup — so hooking
     * connect/getInputStream here catches SSRF without the classpath-scan overhead that
     * hooking {@code URL.openConnection} would impose. The receiver's toString is the full
     * request URL, which the RASP engine inspects for internal/metadata hosts.
     *
     * <p>Installed via the bootstrap injection strategy (the class lives in the java.base
     * module) and relayed through {@link BootstrapBridge}, so it is safe to apply to the
     * platform class loader. Package-private so verification tests can install it on its
     * own when the broader http-client category is disabled.
     */
    static void installSsrfUrlConnectionHooks(Instrumentation instrumentation, File bootstrapDir) {
        bootstrapBuilder(instrumentation, bootstrapDir)
                .type(nameStartsWith("sun.net.www.protocol.http.HttpURLConnection")
                        .or(nameStartsWith("sun.net.www.protocol.https.")))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(BootstrapUrlSinkAdvice.class)
                                .on(namedOneOf("connect", "getInputStream", "getOutputStream"))))
                .installOn(instrumentation);
    }

    static void installSsrfUrlConnectionHooks(Instrumentation instrumentation) {
        installSsrfUrlConnectionHooks(instrumentation, bootstrapDir());
    }

    private static void installJndiHooks(Instrumentation instrumentation, File bootstrapDir) {
        bootstrapBuilder(instrumentation, bootstrapDir)
                .type(hasSuperType(named("javax.naming.Context")))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(BootstrapGenericSinkAdvice.class)
                                .on(namedOneOf("lookup", "lookupLink", "list", "listBindings", "search"))))
                .installOn(instrumentation);

        // 2026-09-28（ldap 族真 sink 覆盖，B 路线前提）：
        // JDK9+ 起 javax.naming 属于 **java.naming 模块**，由 platform classloader 加载，
        // **不在 bootstrap classpath 上**——只走上面那条 bootstrapBuilder 会静默不匹配
        // （fail-open：既不报错也不产事件）。实证：OWASP 靶场 run 32/34 的 ldap_injection
        // 族 6 条 spec 全部 confirmed_exploitable，却 0 条 naming 类探针事件；而历史
        // run 19/20 有 48/11 条 naming 事件（彼时织入路径不同）。
        // 故追加一条 baseBuilder 织入，覆盖 platform 侧的实现类
        // （InitialContext / InitialDirContext / DirContext 实现等），使 ldap 族真 sink
        // （DirContext.search / Context.lookup）可被观测——这是 sink_identity 族一致性
        // 收紧（B 路线）能重评的前提。javax.naming 是导出包，无需 --add-opens。
        baseBuilder()
                .type(hasSuperType(named("javax.naming.Context")))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(BootstrapGenericSinkAdvice.class)
                                .on(namedOneOf("lookup", "lookupLink", "list", "listBindings", "search")))
                        .visit(Advice.to(SinkOutcomeAdvice.class)
                                .on(namedOneOf("lookup", "lookupLink", "list", "listBindings", "search"))))
                .installOn(instrumentation);
    }

    // Reflected-XSS response sink. Spring writes String/HTML response bodies through
    // the message converter's writeInternal; inspecting the outbound body there lets
    // the semantic engine flag <script>/javascript:/on*= payloads before the client
    // receives them. Matched on the converter hierarchy so both String and HTML
    // converters are covered without hooking every PrintWriter.write in the JDK.
    private static void installXssResponseHooks(Instrumentation instrumentation) {
        baseBuilder()
                .type(hasSuperType(named("org.springframework.http.converter.AbstractHttpMessageConverter"))
                        .or(named("org.springframework.http.converter.StringHttpMessageConverter")))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(GenericSinkAdvice.class)
                                .on(named("writeInternal").and(takesArguments(2)))))
                .installOn(instrumentation);
    }

    /**
     * 响应跳转 sink（URL 重定向类漏洞闭环缺口）：hook HttpServletResponse 的 sendRedirect 与
     * setHeader/addHeader(Location)。仅当 Location 头或 sendRedirect 目标含平台 canary 时才经
     * onGenericSink 触发 SINK_REACHED 断言，普通业务流量不误报。
     */
    private static void installResponseRedirectHooks(Instrumentation instrumentation) {
        baseBuilder()
                .type(hasSuperType(named("javax.servlet.http.HttpServletResponse"))
                        .or(hasSuperType(named("jakarta.servlet.http.HttpServletResponse"))))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(ResponseRedirectSinkAdvice.class)
                                .on(named("sendRedirect").and(takesArguments(String.class))))
                        .visit(Advice.to(ResponseRedirectSinkAdvice.class)
                                .on(named("setHeader").and(takesArguments(String.class, String.class))))
                        .visit(Advice.to(ResponseRedirectSinkAdvice.class)
                                .on(named("addHeader").and(takesArguments(String.class, String.class)))))
                .installOn(instrumentation);
    }

    /**
     * XSS 响应体出口 sink（缺口修复）：OWASP Benchmark 等裸 servlet 应用经
     * {@code response.getWriter().println/print/write} 把反射型 XSS 载荷（用户输入）写进响应体，
     * 但 {@link #installXssResponseHooks} 只盖 Spring AbstractHttpMessageConverter，裸 servlet 出口
     * 不可观测 → xss 族稳定 26~27 条 no_evidence。这里把 {@code java.io.PrintWriter} /
     * {@code java.io.PrintStream} 的 write/print/println 织入统一 sink 闸门
     * （BootstrapGenericSinkAdvice → onGenericSink），仅在重放请求带平台 canary（currentCanary 非空）
     * 且响应体含来自请求参数的污点时断言 sink-reached-probe，普通业务流量不误报、fail-open 不影响写路径。
     * 两类均属 java.base，走 bootstrap 注入（BootstrapGenericSinkAdvice 已登记进 BOOTSTRAP 注入列表，
     * 见 injectBootstrapHelpers）。
     */
    private static void installXssServletOutputHooks(Instrumentation instrumentation, File bootstrapDir) {
        bootstrapBuilder(instrumentation, bootstrapDir)
                .type(named("java.io.PrintWriter").or(named("java.io.PrintStream")))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(BootstrapGenericSinkAdvice.class)
                                .on(namedOneOf("write", "print", "println"))))
                .installOn(instrumentation);
    }

    /**
     * Tomcat 响应体出口 sink（Phase1 根因修复，2026-10-11）：裸 servlet 应用（如 OWASP Benchmark）
     * 经 {@code response.getWriter().println(bar)} 把受污染参数写进响应体。{@link
     * #installXssServletOutputHooks} 钩的是 {@code java.io.PrintWriter}，但 Tomcat 运行期实际类型是
     * {@code org.apache.catalina.connector.CoyoteWriter extends PrintWriter}，且 javap 证实它
     * <b>重写了全部</b> write/print/println 方法。ByteBuddy 按类织入：advice 挂在 PrintWriter
     * 自身方法上，子类 override 不调 super 即完全绕过 → 响应体写入路径零事件，xss 族
     * 「到达但值未捕获」(C 类) 与「无事件」(A 类) 缺口由此而来。
     *
     * <p> CoyoteWriter 属 catalina（Tomcat）类、非 java.base，故走 {@link #baseBuilder()}
     * （与 JNDI hook 同构，BootstrapGenericSinkAdvice 已实证可用于 base 类）；复用
     * BootstrapGenericSinkAdvice → onGenericSink，canary 门控防误报（普通流量不产生事件）。
     * 后端确认闸要求 value_hit（canary 真出现在记录值里）才升 confirmed_exploitable，
     * 安全用例（体写 'foo'/'bar'）虽产生到达事件但值级 miss，不会误报。
     */
    private static void installCoyoteWriterHooks(Instrumentation instrumentation) {
        baseBuilder()
                .type(named("org.apache.catalina.connector.CoyoteWriter"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        // 首参 String 的重载：write(String) / write(String,int,int) / print(String) /
                        // println(String) —— Benchmark xss 反射体 println(String) 走这里。
                        .visit(Advice.to(BootstrapGenericSinkAdvice.class)
                                .on(namedOneOf("write", "print", "println")
                                        .and(takesArgument(0, String.class))))
                        // write(char[],int,int)：char 数组体写入路径（resolveCanaryForSink 经
                        // sample() 把 char[] 还原成文本后同样能扫到身份段）。
                        .visit(Advice.to(BootstrapGenericSinkAdvice.class)
                                .on(named("write")
                                        .and(takesArgument(0, char[].class))
                                        .and(takesArgument(1, int.class))
                                        .and(takesArgument(2, int.class)))))
                .installOn(instrumentation);
    }

    /**
     * XPath 求值 sink（缺口修复）：javax.xml.xpath.XPath / XPathExpression 的 evaluate 把攻击者
     * 可控 XPath 表达式交予 XML 引擎求值，是 XPath 注入（xpathi 族）的唯一真 sink，此前无任何 hook →
     * 运行时到达证据拿不到。XPath 类型属 java.xml 模块，走 bootstrap 注入（同 XML/反序列化族）。
     * 复用 BootstrapGenericSinkAdvice → onGenericSink，canary 门控防误报。
     */
    private static void installXPathHooks(Instrumentation instrumentation, File bootstrapDir) {
        bootstrapBuilder(instrumentation, bootstrapDir)
                .type(hasSuperType(named("javax.xml.xpath.XPath"))
                        .or(hasSuperType(named("javax.xml.xpath.XPathExpression"))))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(BootstrapGenericSinkAdvice.class)
                                .on(namedOneOf("evaluate", "compile"))))
                .installOn(instrumentation);

        // 2026-10-14（xpathi 召回恒 0 根因修复）：javax.xml 属 **java.xml 模块**，由 platform
        // classloader 加载，不在 bootstrap classpath 上——只走上面那条 bootstrapBuilder 会**静默
        // 不匹配**（fail-open：不报错也不产事件）。实证：全库 XPath evaluate 事件 = 0，xpathi 族
        // TP 全部 0 召回。与 javax.naming 同型，故追加 baseBuilder 织入覆盖 platform 侧实现类
        // （com.sun.org.apache.xpath.internal.jaxp.XPathImpl 等）。java.xml 是导出包，无需 --add-opens。
        baseBuilder()
                .type(hasSuperType(named("javax.xml.xpath.XPath"))
                        .or(hasSuperType(named("javax.xml.xpath.XPathExpression"))))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(BootstrapGenericSinkAdvice.class)
                                .on(namedOneOf("evaluate", "compile"))))
                .installOn(instrumentation);

        // 具体实现类兜底（2026-10-14，批准修法）：hasSuperType(接口) 对 java.xml 的 platform 实现类
        // 可能匹配不到，故按已知实现类名直连。JDK 8 到 21 的实现类名稳定为
        // com.sun.org.apache.xpath.internal.jaxp.*。走 bootstrapBuilder（java.xml 属 platform loader）。
        for (String _xpImpl : new String[]{
                "com.sun.org.apache.xpath.internal.jaxp.XPathImpl",
                "com.sun.org.apache.xpath.internal.jaxp.XPathExpressionImpl"}) {
            bootstrapBuilder(instrumentation, bootstrapDir)
                    .type(named(_xpImpl))
                    .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                            .visit(Advice.to(BootstrapGenericSinkAdvice.class)
                                    .on(namedOneOf("evaluate", "compile"))))
                    .installOn(instrumentation);
        }
    }

    /**
     * 信任边界违背 sink（trustbound 族，2026-10-14 新增）：{@code HttpSession.setAttribute /
     * putValue} 把请求可控值写入会话作用域，是 trust boundary violation 的真 sink。此前探针
     * **无任何 HttpSession hook** ⇒ trustbound 族召回恒 0（实证 run 351 trustbound 真漏洞
     * no-arrival 7、确认 0）。javax/jakarta.servlet 由容器类加载器加载，走 baseBuilder；复用
     * GenericSinkAdvice → onGenericSink，canary 门控防误报。
     */
    private static void installTrustBoundHooks(Instrumentation instrumentation) {
        baseBuilder()
                .type(hasSuperType(named("javax.servlet.http.HttpSession"))
                        .or(hasSuperType(named("jakarta.servlet.http.HttpSession"))))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(GenericSinkAdvice.class)
                                .on(namedOneOf("setAttribute", "putValue"))))
                .installOn(instrumentation);

        // 具体实现类兜底（2026-10-14，批准修法）：hasSuperType(HttpSession) 对 Tomcat 容器类加载器
        // 加载的实现类可能匹配不到，故按已知 Tomcat 实现类名直连——StandardSessionFacade 是 servlet
        // 拿到的门面（request.getSession() 的返回类型），StandardSession 是真正落库的会话对象。
        baseBuilder()
                .type(named("org.apache.catalina.session.StandardSessionFacade")
                        .or(named("org.apache.catalina.session.StandardSession")))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(GenericSinkAdvice.class)
                                .on(namedOneOf("setAttribute", "putValue"))))
                .installOn(instrumentation);
    }

    /**
     * XStream 反序列化 sink（缺口修复）：com.thoughtworks.xstream.XStream.fromXML 把不可信 XML
     * 反序列化为任意 Java 对象，是 XStream 反序列化 gadget 的唯一真入口，XML hooks 与
     * installPolymorphicDeserHooks 都不盖它 → 此前不可观测。XStream 是应用类加载器类型（fat jar 依赖），
     * 走默认注入策略；复用 GenericSinkAdvice → onGenericSink，canary 门控防误报。
     */
    private static void installXStreamHooks(Instrumentation instrumentation) {
        baseBuilder()
                .type(named("com.thoughtworks.xstream.XStream"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(GenericSinkAdvice.class)
                                .on(named("fromXML"))))
                .installOn(instrumentation);
    }

    private static void installAsyncContextHooks(Instrumentation instrumentation, File bootstrapDir) {
        // 2026-10-31（历史轮次 实证）：**从 hook 范围里摘掉 java.lang.Thread**。
        //
        // 原实现把 java.lang.Thread 的所有构造函数也织入 BootstrapAsyncArgumentAdvice：
        //     .type(named("java.lang.Thread").or(named("CompletableFuture")))
        //     .on(isConstructor().or(isMethod().and(nameContains("Async"))))
        // 而该 Advice 的实现是 `@Advice.AllArguments(readOnly=false) Object[] args`：
        // 每次调用都要把参数整体复制成数组，再逐个 BootstrapBridge.wrapAsyncArgument。
        //
        // 为什么这会致命：Tomcat 8.5 的线程池（TaskThread extends Thread）在线程扩容时
        // 正是靠 `new Thread` 创建 worker。重放把线程池打满 ⇒ 疯狂创建线程 ⇒ 全部挤在
        // 这段 bootstrap 注入的 Advice 上 ⇒ worker 创建被拖死，JVM 活着但不再响应请求。
        // 实测 java-sec-code（Spring Boot 1.5 / 内嵌 Tomcat 8.5.11）：
        //   日志停在某一刻后再无输出，curl 返回 000，堆栈落在
        //   AsyncContext$TaintAwareRunnable.run ← TaskThread$WrappingRunnable.run。
        // 反证：把 max-threads 从 200 加到 500 反而更容易卡 —— 线程创建变多了。
        // Tomcat 9（OWASP Benchmark）之所以没事，是它的 worker 创建时机与数量不同，属侥幸。
        //
        // 收益/代价：在 Thread 构造函数上传播污点收益极低（跨线程本就跨了请求边界，
        // 下游 sink 断言基本用不上），代价却是每次线程创建都过一遍 JDK 核心类的 Advice。
        // CompletableFuture 的 Async 方法已覆盖真正需要的异步传播场景，故只保留它。
        //
        // 注意：Executor / ExecutorService 两段**保留** —— 它们走 HookRuntime.wrapRunnable，
        // 未污染线程有 CircuitBreaker.instrumentationEnabled() 与 Scope.capture()==null
        // 两处短路，开销可忽略，且不触碰 JDK 核心类。
        bootstrapBuilder(instrumentation, bootstrapDir)
                .type(named("java.util.concurrent.CompletableFuture"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(BootstrapAsyncArgumentAdvice.class)
                                .on(isConstructor().or(isMethod().and(nameContains("Async"))))))
                .installOn(instrumentation);

        baseBuilder()
                .type(hasSuperType(named("java.util.concurrent.Executor")))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(ExecutorRunnableAdvice.class)
                                .on(named("execute").and(takesArgument(0, Runnable.class)))))
                .installOn(instrumentation);

        baseBuilder()
                .type(hasSuperType(named("java.util.concurrent.ExecutorService")))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(ExecutorRunnableAdvice.class)
                                .on(named("submit").and(takesArgument(0, Runnable.class))))
                        .visit(Advice.to(ExecutorCallableAdvice.class)
                                .on(named("submit").and(takesArgument(0, java.util.concurrent.Callable.class)))))
                .installOn(instrumentation);
    }

    private static File bootstrapDir() {
        File directory = new File(System.getProperty("java.io.tmpdir"), "sec-probe-bytebuddy");
        if (!directory.exists() && !directory.mkdirs()) {
            AgentLogger.warn("hook", "could not create bootstrap injection directory: " + directory);
        }
        return directory;
    }

    /**
     * 把「会被织入 java.base 类型的 advice / 桥接类」注入 bootstrap 类加载器。
     *
     * <p><b>硬规则（2026-09-14 血泪，禁违反）</b>：只要一个 advice 类的目标类型包含
     * {@code java.base} 类（java.lang.String / java.io.File / java.net.URL / java.nio.file.Paths /
     * java.lang.reflect.Field / java.util.Arrays ...），该 advice 类就必须在本方法里登记
     * {@code ClassInjector...Target.BOOTSTRAP.inject(...)}。原因是 ByteBuddy 把 advice 方法体
     * <i>内联</i>进目标类，内联后的字节码由目标类的加载器（bootstrap）解析，而
     * {@code sec-probe.jar} 只在 system class path 上、bootstrap 看不见。
     *
     * <p>漏登记的后果不是「该族静默失效」，而是<b>应用全线 500</b>：bootstrap 解析不到 advice 类
     * → 每次执行到被织入的方法就抛 {@code NoClassDefFoundError}，Tomcat dispatcherServlet 直接挂掉。
     * 2026-09-14 的 {@code PropagateBoundaryAdvice} 与更早的 {@code BoundaryTaintSupport}
     * 两次事故都是漏登记，不是「advice 不能引用新增类」——新增类只要一并登记就能用。
     *
     * <p>另外 {@code ClassInjector.UsingInstrumentation.of(...)} 与 {@code Map.of} 都卡 10 个
     * (type, bytes) 对，所以按批拆分，新加的类另起一批即可。
     */
    private static void injectBootstrapHelpers(Instrumentation instrumentation, File bootstrapDir) {
        // ClassInjector.UsingInstrumentation.of(...) caps at 10 (type, bytes) pairs and
        // Map.of at 10 entries, so split the bootstrap classes across two inject calls.
        FailOpen.run("bytebuddy-bootstrap-inject", () -> {
            ClassInjector.UsingInstrumentation.of(bootstrapDir,
                            ClassInjector.UsingInstrumentation.Target.BOOTSTRAP, instrumentation)
                    .inject(Map.of(
                            TypeDescription.ForLoadedType.of(BootstrapBridge.class),
                            ClassFileLocator.ForClassLoader.read(BootstrapBridge.class),
                            TypeDescription.ForLoadedType.of(BootstrapGenericSinkAdvice.class),
                            ClassFileLocator.ForClassLoader.read(BootstrapGenericSinkAdvice.class),
                            TypeDescription.ForLoadedType.of(BootstrapProcessBuilderStartAdvice.class),
                            ClassFileLocator.ForClassLoader.read(BootstrapProcessBuilderStartAdvice.class),
                            TypeDescription.ForLoadedType.of(BootstrapAsyncArgumentAdvice.class),
                            ClassFileLocator.ForClassLoader.read(BootstrapAsyncArgumentAdvice.class),
                            TypeDescription.ForLoadedType.of(BootstrapUrlSinkAdvice.class),
                            ClassFileLocator.ForClassLoader.read(BootstrapUrlSinkAdvice.class),
                            TypeDescription.ForLoadedType.of(TaintStore.class),
                            ClassFileLocator.ForClassLoader.read(TaintStore.class)));
            ClassInjector.UsingInstrumentation.of(bootstrapDir,
                            ClassInjector.UsingInstrumentation.Target.BOOTSTRAP, instrumentation)
                    .inject(Map.of(
                            TypeDescription.ForLoadedType.of(PropagateStringAdvice.class),
                            ClassFileLocator.ForClassLoader.read(PropagateStringAdvice.class),
                            TypeDescription.ForLoadedType.of(PropagateStringConcatAdvice.class),
                            ClassFileLocator.ForClassLoader.read(PropagateStringConcatAdvice.class),
                            TypeDescription.ForLoadedType.of(PropagateValueOfObjectAdvice.class),
                            ClassFileLocator.ForClassLoader.read(PropagateValueOfObjectAdvice.class),
                            TypeDescription.ForLoadedType.of(PropagateValueOfIntAdvice.class),
                            ClassFileLocator.ForClassLoader.read(PropagateValueOfIntAdvice.class),
                            TypeDescription.ForLoadedType.of(PropagateValueOfLongAdvice.class),
                            ClassFileLocator.ForClassLoader.read(PropagateValueOfLongAdvice.class),
                            TypeDescription.ForLoadedType.of(PropagateStringBuilderAppendAdvice.class),
                            ClassFileLocator.ForClassLoader.read(PropagateStringBuilderAppendAdvice.class),
                            TypeDescription.ForLoadedType.of(PropagateStringBuilderToStringAdvice.class),
                            ClassFileLocator.ForClassLoader.read(PropagateStringBuilderToStringAdvice.class),
                            TypeDescription.ForLoadedType.of(PropagateDecodeAdvice.class),
                            ClassFileLocator.ForClassLoader.read(PropagateDecodeAdvice.class),
                            TypeDescription.ForLoadedType.of(PropagatePrimitiveAdvice.class),
                            ClassFileLocator.ForClassLoader.read(PropagatePrimitiveAdvice.class)));
            // 3rd inject: remaining bootstrap helpers (kept under the 10-pair Map.of /
            // ClassInjector limit). PropagateStringValueOfAdvice was split into the
            // Object/Int/Long valueOf advices above; the numeric append variants and the
            // reflection sink advice go here.
            ClassInjector.UsingInstrumentation.of(bootstrapDir,
                            ClassInjector.UsingInstrumentation.Target.BOOTSTRAP, instrumentation)
                    .inject(Map.of(
                            TypeDescription.ForLoadedType.of(ReflectionClassLoadAdvice.class),
                            ClassFileLocator.ForClassLoader.read(ReflectionClassLoadAdvice.class),
                            TypeDescription.ForLoadedType.of(ReflectionInvokeAdvice.class),
                            ClassFileLocator.ForClassLoader.read(ReflectionInvokeAdvice.class),
                            TypeDescription.ForLoadedType.of(PropagateStringBuilderAppendIntAdvice.class),
                            ClassFileLocator.ForClassLoader.read(PropagateStringBuilderAppendIntAdvice.class),
                            TypeDescription.ForLoadedType.of(PropagateStringBuilderAppendLongAdvice.class),
                            ClassFileLocator.ForClassLoader.read(PropagateStringBuilderAppendLongAdvice.class),
                            TypeDescription.ForLoadedType.of(PropagateStringBuilderCtorAdvice.class),
                            ClassFileLocator.ForClassLoader.read(PropagateStringBuilderCtorAdvice.class)));
            // 4th inject: M2 propagation-completeness advices (String.format/join/split/
            // constructor, StringBuilder insert/replace/appendObj/substring, StringJoiner
            // merge, Base64 codec). 10 pairs == Map.of ceiling.
            ClassInjector.UsingInstrumentation.of(bootstrapDir,
                            ClassInjector.UsingInstrumentation.Target.BOOTSTRAP, instrumentation)
                    .inject(Map.of(
                            TypeDescription.ForLoadedType.of(PropagateStringFormatAdvice.class),
                            ClassFileLocator.ForClassLoader.read(PropagateStringFormatAdvice.class),
                            TypeDescription.ForLoadedType.of(PropagateStringJoinAdvice.class),
                            ClassFileLocator.ForClassLoader.read(PropagateStringJoinAdvice.class),
                            TypeDescription.ForLoadedType.of(PropagateStringSplitAdvice.class),
                            ClassFileLocator.ForClassLoader.read(PropagateStringSplitAdvice.class),
                            TypeDescription.ForLoadedType.of(PropagateStringBuilderInsertAdvice.class),
                            ClassFileLocator.ForClassLoader.read(PropagateStringBuilderInsertAdvice.class),
                            TypeDescription.ForLoadedType.of(PropagateStringBuilderReplaceAdvice.class),
                            ClassFileLocator.ForClassLoader.read(PropagateStringBuilderReplaceAdvice.class),
                            TypeDescription.ForLoadedType.of(PropagateStringBuilderAppendObjAdvice.class),
                            ClassFileLocator.ForClassLoader.read(PropagateStringBuilderAppendObjAdvice.class),
                            TypeDescription.ForLoadedType.of(PropagateStringBuilderSubstringAdvice.class),
                            ClassFileLocator.ForClassLoader.read(PropagateStringBuilderSubstringAdvice.class),
                            TypeDescription.ForLoadedType.of(PropagateStringJoinerMergeAdvice.class),
                            ClassFileLocator.ForClassLoader.read(PropagateStringJoinerMergeAdvice.class),
                            TypeDescription.ForLoadedType.of(PropagateBase64Advice.class),
                            ClassFileLocator.ForClassLoader.read(PropagateBase64Advice.class),
                            TypeDescription.ForLoadedType.of(PropagateStringCtorAdvice.class),
                            ClassFileLocator.ForClassLoader.read(PropagateStringCtorAdvice.class)));
            // 5th inject: field-level taint edges (java.lang.reflect.Field) and array
            // reorganisation (java.util.Arrays). Both target java.base types, so the advice
            // classes must be visible from the bootstrap loader like every other advice above.
            ClassInjector.UsingInstrumentation.of(bootstrapDir,
                            ClassInjector.UsingInstrumentation.Target.BOOTSTRAP, instrumentation)
                    .inject(Map.of(
                            TypeDescription.ForLoadedType.of(ReflectFieldGetAdvice.class),
                            ClassFileLocator.ForClassLoader.read(ReflectFieldGetAdvice.class),
                            TypeDescription.ForLoadedType.of(ReflectFieldSetAdvice.class),
                            ClassFileLocator.ForClassLoader.read(ReflectFieldSetAdvice.class),
                            TypeDescription.ForLoadedType.of(PropagateArrayCopyAdvice.class),
                            ClassFileLocator.ForClassLoader.read(PropagateArrayCopyAdvice.class)));
            // 6th inject: 类型边界传播 advice (String -> 载体)。目标 java.io.File / java.net.URL /
            // java.nio.file.Paths / java.io.StringReader / ByteArrayInputStream 全在 java.base，
            // advice 类必须显式注入 bootstrap，否则织入 java.base 的字节码在运行时解析不到
            // com/rasp/probe/PropagateBoundaryAdvice → NoClassDefFoundError → dispatcherServlet 500
            // （2026-09-14 实测：8092 全线 500，/login /products 均失败）。
            ClassInjector.UsingInstrumentation.of(bootstrapDir,
                            ClassInjector.UsingInstrumentation.Target.BOOTSTRAP, instrumentation)
                    .inject(Map.of(
                            TypeDescription.ForLoadedType.of(PropagateBoundaryAdvice.class),
                            ClassFileLocator.ForClassLoader.read(PropagateBoundaryAdvice.class),
                            TypeDescription.ForLoadedType.of(PropagateBoundaryStaticAdvice.class),
                            ClassFileLocator.ForClassLoader.read(PropagateBoundaryStaticAdvice.class),
                            // 反序列化构造器传播（2026-09-28 第三层）：ObjectInputStream 在 java.base，
                            // advice 类必须显式注入 bootstrap，否则织入后运行时解析不到
                            // → NoClassDefFoundError → 靶场全线 500（2026-09-14 同类事故）。
                            TypeDescription.ForLoadedType.of(PropagateObjectStreamCtorAdvice.class),
                            ClassFileLocator.ForClassLoader.read(PropagateObjectStreamCtorAdvice.class)));
        });
    }

    /**
     * L2 data-flow propagation hooks (手册 11.1.x). String/StringBuilder/StringBuffer/
     * StringJoiner/URLDecoder/primitive-parse are java.base types, so they are
     * installed via the bootstrap injection strategy. These catch the common
     * "变形绕过" (concatenation, case/encoding, numeric) so a tainted source is
     * traced to the sink even after transformation.
     *
     * ByteBuddy constraint: each @OnMethodExit method lives in its own advice class
     * (or a class whose methods have disjoint annotation-role sets) — two methods
     * binding the same roles (e.g. This+Argument(0) or Argument(0)+Return) in one
     * class throw "Duplicate advice" and abort the whole install.
     */
    private static void installPropagatorHooks(Instrumentation instrumentation, File bootstrapDir) {
        bootstrapBuilder(instrumentation, bootstrapDir)
                .type(named("java.lang.String"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(PropagateStringConcatAdvice.class).on(named("concat")))
                        .visit(Advice.to(PropagateValueOfObjectAdvice.class)
                                .on(named("valueOf").and(takesArgument(0, Object.class))))
                        .visit(Advice.to(PropagateValueOfIntAdvice.class)
                                .on(named("valueOf").and(takesArgument(0, int.class))))
                        .visit(Advice.to(PropagateValueOfLongAdvice.class)
                                .on(named("valueOf").and(takesArgument(0, long.class))))
                        .visit(Advice.to(PropagateStringAdvice.class)
                                .on(namedOneOf("substring", "replace", "toUpperCase", "toLowerCase",
                                        "trim", "strip", "stripLeading", "stripTrailing", "repeat",
                                        "replaceAll", "replaceFirst", "intern")))
                        .visit(Advice.to(PropagateStringFormatAdvice.class).on(named("format")))
                        .visit(Advice.to(PropagateStringJoinAdvice.class).on(named("join")))
                        .visit(Advice.to(PropagateStringSplitAdvice.class).on(named("split")))
                        .visit(Advice.to(PropagateStringCtorAdvice.class)
                                .on(isConstructor().and(takesArguments(1))
                                        .and(takesArgument(0, String.class)
                                                .or(takesArgument(0, char[].class))
                                                .or(takesArgument(0, byte[].class))))))
                .installOn(instrumentation);

        bootstrapBuilder(instrumentation, bootstrapDir)
                .type(named("java.lang.StringBuilder").or(named("java.lang.StringBuffer")).or(named("java.util.StringJoiner")))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(PropagateStringBuilderAppendAdvice.class)
                                .on(named("append").and(takesArgument(0, String.class))
                                        .or(named("append").and(takesArgument(0, CharSequence.class)))
                                        .or(named("append").and(takesArgument(0, char[].class)))
                                        .or(named("add").and(takesArgument(0, CharSequence.class)))))
                        .visit(Advice.to(PropagateStringBuilderCtorAdvice.class)
                                .on(isConstructor().and(takesArgument(0, String.class)
                                        .or(takesArgument(0, CharSequence.class)))))
                        .visit(Advice.to(PropagateStringBuilderAppendIntAdvice.class)
                                .on(named("append").and(takesArgument(0, int.class))))
                        .visit(Advice.to(PropagateStringBuilderAppendLongAdvice.class)
                                .on(named("append").and(takesArgument(0, long.class))))
                        .visit(Advice.to(PropagateStringBuilderAppendObjAdvice.class)
                                .on(named("append").and(takesArgument(0, Object.class))
                                        .or(named("append").and(takesArgument(0, boolean.class)))
                                        .or(named("append").and(takesArgument(0, char.class)))
                                        .or(named("append").and(takesArgument(0, float.class)))
                                        .or(named("append").and(takesArgument(0, double.class)))
                                        .or(named("appendCodePoint").and(takesArgument(0, int.class)))))
                        .visit(Advice.to(PropagateStringBuilderInsertAdvice.class)
                                .on(named("insert").and(takesArgument(1, CharSequence.class))
                                        .or(named("insert").and(takesArgument(1, char[].class)))
                                        .or(named("insert").and(takesArgument(1, Object.class)))
                                        .or(named("insert").and(takesArgument(1, char.class)))))
                        .visit(Advice.to(PropagateStringBuilderReplaceAdvice.class)
                                .on(named("replace").and(takesArgument(2, String.class))))
                        .visit(Advice.to(PropagateStringBuilderSubstringAdvice.class).on(named("substring")))
                        .visit(Advice.to(PropagateStringJoinerMergeAdvice.class).on(named("merge")))
                        .visit(Advice.to(PropagateStringBuilderToStringAdvice.class).on(named("toString"))))
                .installOn(instrumentation);

        bootstrapBuilder(instrumentation, bootstrapDir)
                .type(named("java.net.URLDecoder"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(PropagateDecodeAdvice.class).on(named("decode"))))
                .installOn(instrumentation);

        bootstrapBuilder(instrumentation, bootstrapDir)
                .type(named("java.lang.Integer"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(PropagatePrimitiveAdvice.class).on(named("parseInt"))))
                .installOn(instrumentation);

        bootstrapBuilder(instrumentation, bootstrapDir)
                .type(named("java.lang.Long"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(PropagatePrimitiveAdvice.class).on(named("parseLong"))))
                .installOn(instrumentation);

        bootstrapBuilder(instrumentation, bootstrapDir)
                .type(named("java.lang.Double"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(PropagatePrimitiveAdvice.class).on(named("parseDouble"))))
                .installOn(instrumentation);

        bootstrapBuilder(instrumentation, bootstrapDir)
                .type(named("java.util.Base64$Decoder").or(named("java.util.Base64$Encoder")))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(PropagateBase64Advice.class)
                                .on(named("decode").or(named("encode")).or(named("encodeToString")))))
                .installOn(instrumentation);

        // ---- 11.1.8 Third-party library string-transformation propagation ----        // These are application-classloader types (not java.base), so they are
        // installed with the default (UsingUnsafe) injection strategy — the same
        // mechanism the framework hooks (Redis/Dubbo/MyBatis) use. The advices live
        // in com.rasp.probe and reference the bootstrap TaintStore, shared with
        // every other hook, so no bootstrap injection is required here.
        installThirdPartyPropagatorHooks(instrumentation);
    }

    /**
     * 类型边界传播 (F2 修复): 被污染 String 经载体类 (StringReader / ByteArrayInputStream /
     * File / URL / Path / InputSource) 包裹后，原 String 内容在载体里取不到 (toString/getSystemId
     * 只剩 class@hash)，导致 sink 处 canary 现场断言在 String->载体 边界丢失，XXE / 路径穿越 /
     * 文件上传等族永远 no-arrival。本方法在载体构造时刻把源内容按载体身份登记进 TaintHub.CARRIER_CONTENT，
     * 由 HookRuntime.sample() 在 sink 处兜底回收。载体均为 java.base / java.xml 类型，走 bootstrap 注入。
     */
    private static void installBoundaryHooks(Instrumentation instrumentation, File bootstrapDir) {
        bootstrapBuilder(instrumentation, bootstrapDir)
                .type(named("java.io.StringReader")
                        .or(named("java.io.ByteArrayInputStream"))
                        .or(named("java.io.File"))
                        .or(named("java.net.URL"))
                        .or(named("java.nio.file.Paths"))
                        .or(named("org.xml.sax.InputSource")))
                // 2026-09-14：必须拆成两个 advice 类 + 两个互斥匹配器。
                // 同一 advice 类含两个 @OnMethodExit 时 ByteBuddy 1.15.11 抛
                // "Duplicate advice for Delegate to ...onCtor(...) and ...onStatic(...)"，
                // 六个边界类整类插桩失败（日志 152 次）。
                // 两个 advice 类各自自包含（辅助方法 public static，不引用任何新增类），
                // 否则 bootstrap 域解析不到新类，会连累 java.lang.Class / ClassLoader / Method /
                // Field / Thread / Executor* 等一批 java.base 类 NoClassDefFoundError。
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(PropagateBoundaryAdvice.class)
                                .on(isConstructor().and(not(takesArguments(0))))))
                .installOn(instrumentation);

        // Paths.get(...) 静态工厂形态：Paths 无公开构造器，所有路径创建必经 Paths.get。
        // 与构造器形态 PropagateBoundaryAdvice 拆成两个 advice 类（同 matcher 下两个
        // @OnMethodExit 会触发 ByteBuddy「Duplicate advice」整类插桩失败，见 PropagateBoundaryAdvice 注释）。
        // Paths 属 java.base，advice 类已登记进 injectBootstrapHelpers 的 BOOTSTRAP 注入（第 6 批）。
        // 只匹配 get(String, ...)（arg0 为路径首段字符串）；get(URI) 的 arg0 是 URI，无需传播，由 matcher 排除。
        bootstrapBuilder(instrumentation, bootstrapDir)
                .type(named("java.nio.file.Paths"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(PropagateBoundaryStaticAdvice.class)
                                .on(named("get").and(takesArgument(0, String.class)))))
                .installOn(instrumentation);
    }

    /**
     * 11.1.8 third-party library string transforms (手册 11.1.8 二~⑦).
     *
     * <p>Each library's high-frequency string transformation methods are hooked so a
     * tainted source is traced through them to the sink even after transformation.
     * The common pattern is "result inherits the taint of argument 0" (the subject),
     * handled by {@link PropagateLibStringAdvice}; sanitizer escape* methods clear
     * taint on output ({@link PropagateLibEscapeAdvice}), while their unescape*
     * counterparts propagate (handled by PropagateLibStringAdvice).
     */
    private static void installThirdPartyPropagatorHooks(Instrumentation instrumentation) {
        // ① Apache Commons Lang3 StringUtils — replace/join/substring/case/...
        baseBuilder()
                .type(named("org.apache.commons.lang3.StringUtils"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(PropagateLibStringAdvice.class).on(namedOneOf(
                                "replace", "replaceEach", "replaceChars", "join", "substring",
                                "upperCase", "lowerCase", "capitalize", "uncapitalize", "reverse",
                                "deleteWhitespace", "strip", "stripStart", "stripEnd", "trim",
                                "left", "right", "mid", "repeat", "abbreviate", "defaultString",
                                "normalizeSpace", "chomp", "chop"))))
                .installOn(instrumentation);

        // ② Apache Commons Text StringEscapeUtils — sanitizer. escape* clears taint;
        // unescape* re-introduces raw (dangerous) content and inherits taint.
        baseBuilder()
                .type(named("org.apache.commons.text.StringEscapeUtils"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(PropagateLibEscapeAdvice.class).on(namedOneOf(
                                "escapeHtml3", "escapeHtml4", "escapeXml", "escapeXml11", "escapeXml10",
                                "escapeJava", "escapeEcmaScript", "escapeJson", "escapeCsv")))
                        .visit(Advice.to(PropagateLibStringAdvice.class).on(namedOneOf(
                                "unescapeHtml3", "unescapeHtml4", "unescapeXml", "unescapeJava",
                                "unescapeEcmaScript", "unescapeJson", "unescapeCsv"))))
                .installOn(instrumentation);

        // ③ Spring StringUtils — cleanPath (path-traversal normalization) et al.
        baseBuilder()
                .type(named("org.springframework.util.StringUtils"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(PropagateLibStringAdvice.class).on(namedOneOf(
                                "replace", "trimWhitespace", "capitalize", "uncapitalize", "getFilename",
                                "stripFilenameExtension", "collectionToDelimitedString",
                                "arrayToDelimitedString", "quote", "unqualify", "delete", "cleanPath"))))
                .installOn(instrumentation);

        // ④ Spring HtmlUtils — XSS sanitizer (clear on escape).
        baseBuilder()
                .type(named("org.springframework.web.util.HtmlUtils"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(PropagateLibEscapeAdvice.class).on(namedOneOf("htmlEscape")))
                        .visit(Advice.to(PropagateLibStringAdvice.class).on(namedOneOf("htmlUnescape"))))
                .installOn(instrumentation);

        // ⑤ Guava Strings / Joiner / CharMatcher.
        baseBuilder()
                .type(named("com.google.common.base.Strings"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(PropagateLibStringAdvice.class).on(namedOneOf(
                                "emptyToNull", "nullToEmpty", "padStart", "padEnd", "repeat",
                                "commonPrefix", "commonSuffix"))))
                .installOn(instrumentation);

        baseBuilder()
                .type(named("com.google.common.base.Joiner"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(PropagateLibStringAdvice.class).on(named("join"))))
                .installOn(instrumentation);

        baseBuilder()
                .type(named("com.google.common.base.CharMatcher"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(PropagateLibStringAdvice.class).on(namedOneOf(
                                "retainFrom", "removeFrom", "replaceFrom"))))
                .installOn(instrumentation);

        // ⑥ Apache Commons IO FilenameUtils — path normalization.
        baseBuilder()
                .type(named("org.apache.commons.io.FilenameUtils"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(PropagateLibStringAdvice.class).on(namedOneOf(
                                "normalize", "concat", "getFullPath", "getName", "getPath",
                                "removeExtension", "separatorsToUnix", "separatorsToWindows",
                                "getExtension", "getBaseName"))))
                .installOn(instrumentation);

        // ⑦ Apache Commons Lang3 RegExUtils — 正则改写/替换（replacePattern/removePattern 等）
        // 把被污染字符串经正则改写后，污点若不继承会继续误判 no-arrival（与 StringUtils 同病）。
        baseBuilder()
                .type(named("org.apache.commons.lang3.RegExUtils"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(PropagateLibStringAdvice.class).on(namedOneOf(
                                "replacePattern", "removePattern", "removeAll", "replaceAll"))))
                .installOn(instrumentation);
    }

    /**
     * L2 reflection sink (手册 11.1.2 决策④ + 11.1.3 十·⑦). Class.forName/loadClass
     * with a tainted name, and Method.invoke/Constructor.newInstance with a tainted
     * String argument, become interception points for reflection-based RCE.
     */
    private static void installReflectionSinkHooks(Instrumentation instrumentation, File bootstrapDir) {
        bootstrapBuilder(instrumentation, bootstrapDir)
                .type(named("java.lang.Class"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(ReflectionClassLoadAdvice.class).on(named("forName"))))
                .installOn(instrumentation);

        bootstrapBuilder(instrumentation, bootstrapDir)
                .type(named("java.lang.ClassLoader"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(ReflectionClassLoadAdvice.class).on(named("loadClass"))))
                .installOn(instrumentation);

        bootstrapBuilder(instrumentation, bootstrapDir)
                .type(named("java.lang.reflect.Method"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(ReflectionInvokeAdvice.class).on(named("invoke"))))
                .installOn(instrumentation);

        bootstrapBuilder(instrumentation, bootstrapDir)
                .type(named("java.lang.reflect.Constructor"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(ReflectionInvokeAdvice.class).on(named("newInstance"))))
                .installOn(instrumentation);
    }

    /**
     * 字段级污点边 (手册 11.1.3 十.1). {@code Field.get} / {@code Field.set} are the boundary
     * every framework binder (Jackson databind, Spring data binding, BeanUtils, MyBatis
     * result mapping) crosses when it stashes request data into a POJO and later reads it
     * back. Without these edges the taint chain snaps at the DTO: user input goes in, comes
     * back out "clean", and reaches the sink unmarked.
     *
     * <p>Matched on {@code get(Object)} / {@code set(Object,Object)} only — the primitive
     * accessors ({@code getInt}, {@code setLong}, …) return/accept primitives that carry no
     * object identity, so there is nothing to mark and hooking them would be pure overhead.
     */
    private static void installFieldTaintHooks(Instrumentation instrumentation, File bootstrapDir) {
        bootstrapBuilder(instrumentation, bootstrapDir)
                .type(named("java.lang.reflect.Field"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(ReflectFieldGetAdvice.class)
                                .on(named("get").and(takesArguments(1))))
                        .visit(Advice.to(ReflectFieldSetAdvice.class)
                                .on(named("set").and(takesArguments(2)))))
                .installOn(instrumentation);
    }

    /**
     * 数组重组传播 (手册 11.1.3 十.5). {@code Arrays.copyOf} / {@code copyOfRange} are the
     * instrumentable half of array reorganisation — {@code System.arraycopy} and
     * {@code array.clone()} are native/intrinsic and can never be woven.
     *
     * <p>Only the reference-array overloads ({@code Object[]}, {@code byte[]}, {@code char[]})
     * are matched: those are the ones that carry attacker data (request-body buffers, split
     * results, decoded payloads). The numeric overloads ({@code int[]}, {@code long[]}, …)
     * hold no markable object identity, and skipping them keeps this hook off the hottest
     * JDK paths.
     */
    private static void installArrayTaintHooks(Instrumentation instrumentation, File bootstrapDir) {
        bootstrapBuilder(instrumentation, bootstrapDir)
                .type(named("java.util.Arrays"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(PropagateArrayCopyAdvice.class)
                                .on(namedOneOf("copyOf", "copyOfRange")
                                        .and(takesArgument(0, Object[].class)
                                                .or(takesArgument(0, byte[].class))
                                                .or(takesArgument(0, char[].class))))))
                .installOn(instrumentation);
    }

    // ---- M2 盲点 sink 家族 (手册 11.4.1 / 11.4.2) ----

    /**
     * The four sink families the manual calls out as blind spots and that had ZERO hook
     * coverage before: polymorphic deserialization, NoSQL injection, server-side template
     * injection (SSTI) and GraphQL. All four are application-classloader types, so they use
     * the default injection strategy and the agent-loader {@link GenericSinkAdvice} — the
     * same mechanism as the Redis/Dubbo/ES framework hooks.
     *
     * <p>These sinks are routed through {@link HookRuntime#onGenericSink}, so the taint gate
     * decides first and the family-specific content判定 ({@code TAINT_ONLY_ATTACK} in
     * {@link RaspSemanticEngine}) only applies to values that actually carry taint. A backend
     * service issuing its own legitimate Mongo query or rendering its own template therefore
     * cannot be false-blocked.
     */
    private static void installBlindSpotSinkHooks(Instrumentation instrumentation, File bootstrapDir) {
        installPolymorphicDeserHooks(instrumentation);
        installNoSqlHooks(instrumentation);
        installTemplateEngineHooks(instrumentation);
        installGraphQlHooks(instrumentation);
        installWeakCryptoHooks(instrumentation, bootstrapDir);
    }

    // 方案 B（2026-09-25）：weakrand / crypto / hash / securecookie 四族真 sink 补桩。
    // 此前这四族零 hook（grep 计数=0），benchmark 重放即使执行到 new Random() /
    // Cipher.getInstance("DES") / MessageDigest.getInstance("MD5") / Cookie.setSecure(false)
    // 也无任何探针事件，D2 永远 no_evidence，被迫靠「弱确认口径」折算——现补齐观测点闭环。
    // 全部复用 GenericSinkAdvice：sink 名经 @Advice.Origin 自动带出（如 java.util.Random.nextInt），
    // canaried 重放请求命中即 sink-reached 断言（onGenericSink 既有分支），普通流量走 L1 签名观测，
    // CircuitBreaker/HookMetrics 频控与 isSelfOriginated 自指防护照常生效。
    private static void installWeakCryptoHooks(Instrumentation instrumentation, File bootstrapDir) {
        // 2026-10-08 根因修复（决定性实证）：
        // 上面三条（java.util.Random / javax.crypto.Cipher / java.security.MessageDigest）此前用
        // baseBuilder() + GenericSinkAdvice 织入，而它们都是 **java.base 模块、bootstrap 类加载器**
        // 的类——baseBuilder 的 InjectionStrategy.UsingUnsafe 无法把 advice 注入 bootstrap loader，
        // ByteBuddy 织入静默失败（既不报错也不产事件）。实证：run 246 的 2220 条 iast_events 里
        // sink_file 分布只有 FileInputStream/FileOutputStream/DocumentBuilder/ProcessBuilder/
        // Runtime/RandomAccessFile/JDBC Statement/sendRedirect/setHeader/Files.newInputStream，
        // MessageDigest / Cipher / Random / Cookie 命中数全为 0（注意 "Random" 的 42 条是
        // java.io.RandomAccessFile 的子串误匹配，不是 java.util.Random）。
        // 对照组：同为 java.base 的 java.io.FileInputStream（1267 条事件，工作正常）用的正是
        // bootstrapBuilder + BootstrapGenericSinkAdvice。⇒ 本四族改用同一条已验证可行的织入路径。
        // 后果：这四族 D2 永远拿不到真 sink 证据，judge_algorithm/random/attribute 三个判据函数
        // 即使代码接通也是空转（无事件可判），只能退回「借别族 sink 确认」→ FP 与 TP 一起确认。

        // weakrand：java.util.Random 随机值产出点（nextInt 为主，OWASP Benchmark CWE-330 形态）。
        // 用 BootstrapRandomSourceAdvice（而非 BootstrapGenericSinkAdvice）：
        // 后者会被 Cipher/MessageDigest 等静态方法复用，无法加 @Advice.This；
        // 前者在 advice 内看 receiver 真实类型，CSPRNG 子类（SecureRandom 继承陷阱）直接跳过，
        // 从根上消除「SecureRandom.nextDouble 被当成弱随机源」的误报。
        bootstrapBuilder(instrumentation, bootstrapDir)
                .type(named("java.util.Random"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(BootstrapRandomSourceAdvice.class)
                                .on(namedOneOf("nextInt", "nextLong", "nextDouble", "nextFloat", "nextBoolean"))))
                .installOn(instrumentation);

        // crypto：Cipher.getInstance(算法名) —— 算法串即实参样本（DES/RC4/ECB…，CWE-327）。
        bootstrapBuilder(instrumentation, bootstrapDir)
                .type(named("javax.crypto.Cipher"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(BootstrapGenericSinkAdvice.class)
                                .on(named("getInstance"))))
                .installOn(instrumentation);

        // hash：MessageDigest.getInstance(算法名)（MD5/SHA-1…，CWE-328，配合 sastai weak-hash 查询）。
        bootstrapBuilder(instrumentation, bootstrapDir)
                .type(named("java.security.MessageDigest"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(BootstrapGenericSinkAdvice.class)
                                .on(named("getInstance"))))
                .installOn(instrumentation);

        // securecookie：javax + jakarta 双包名（应用类加载器，走 baseBuilder 即可）。
        // 2026-10-08 补 <init>：OWASP Benchmark 的 securecookie **真漏洞形态是「创建 Cookie 但
        // 从不设 flag」**，只 hook setSecure/setHttpOnly 永远抓不到（设了 flag 的反而是 safe 用例）。
        // 补上构造器 hook 后，「有 Cookie.<init> 但无 setSecure(true)/setHttpOnly(true)」即可作为
        // 「flag 缺失」的正向证据 —— 这正是 family_verdict.judge_attribute_family 一直在等的输入。
        baseBuilder()
                .type(named("javax.servlet.http.Cookie")
                        .or(named("jakarta.servlet.http.Cookie")))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(GenericSinkAdvice.class)
                                .on(namedOneOf("setSecure", "setHttpOnly")))
                        .visit(Advice.to(GenericSinkAdvice.class).on(isConstructor())))
                .installOn(instrumentation);
    }

    // ① 多态反序列化 (Jackson enableDefaultTyping / @type gadget, fastjson, snakeyaml).
    // The entry method receives the raw document, so the gadget type key (@type / _class /
    // !!javax.script...) is visible in the sink sample and to the taint deep scan.
    private static void installPolymorphicDeserHooks(Instrumentation instrumentation) {
        baseBuilder()
                .type(named("com.fasterxml.jackson.databind.ObjectMapper")
                        .or(named("com.fasterxml.jackson.databind.ObjectReader"))
                        .or(named("org.codehaus.jackson.map.ObjectMapper")))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(GenericSinkAdvice.class)
                                .on(namedOneOf("readValue", "readValues", "treeToValue", "convertValue"))))
                .installOn(instrumentation);

        baseBuilder()
                .type(named("com.alibaba.fastjson.JSON")
                        .or(named("com.alibaba.fastjson2.JSON")))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(GenericSinkAdvice.class)
                                .on(namedOneOf("parse", "parseObject", "parseArray"))))
                .installOn(instrumentation);

        baseBuilder()
                .type(named("org.yaml.snakeyaml.Yaml"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(GenericSinkAdvice.class)
                                .on(namedOneOf("load", "loadAll", "loadAs"))))
                .installOn(instrumentation);
    }

    // ② NoSQL 注入 ($where / $regex / $expr 操作符走私). MongoCollection is an interface, so
    // hasSuperType matches the driver's concrete impl; MongoTemplate is a concrete class.
    private static void installNoSqlHooks(Instrumentation instrumentation) {
        baseBuilder()
                .type(hasSuperType(named("com.mongodb.client.MongoCollection")))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(GenericSinkAdvice.class)
                                .on(namedOneOf("find", "aggregate", "countDocuments", "distinct", "mapReduce",
                                        "deleteOne", "deleteMany", "updateOne", "updateMany",
                                        "findOneAndUpdate", "findOneAndDelete", "findOneAndReplace"))))
                .installOn(instrumentation);

        baseBuilder()
                .type(named("org.springframework.data.mongodb.core.MongoTemplate"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(GenericSinkAdvice.class)
                                .on(namedOneOf("find", "findOne", "findAll", "count", "exists", "remove",
                                        "updateFirst", "updateMulti", "upsert", "aggregate",
                                        "findAndModify", "findAndRemove", "executeCommand"))))
                .installOn(instrumentation);
    }

    // ③ SSTI: the template SOURCE (not the model) is the injection point, so the hooks sit on
    // the methods that accept or compile a template string / expression.
    private static void installTemplateEngineHooks(Instrumentation instrumentation) {
        baseBuilder()
                .type(named("freemarker.template.Template")
                        .or(named("freemarker.cache.StringTemplateLoader")))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(GenericSinkAdvice.class)
                                .on(namedOneOf("process", "putTemplate").or(isConstructor()))))
                .installOn(instrumentation);

        baseBuilder()
                .type(named("org.apache.velocity.app.VelocityEngine")
                        .or(named("org.apache.velocity.app.Velocity"))
                        .or(named("org.apache.velocity.runtime.RuntimeInstance")))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(GenericSinkAdvice.class)
                                .on(namedOneOf("evaluate", "mergeTemplate", "getTemplate", "parse"))))
                .installOn(instrumentation);

        baseBuilder()
                .type(named("org.thymeleaf.TemplateEngine")
                        .or(hasSuperType(named("org.thymeleaf.standard.expression.IStandardExpressionParser"))))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(GenericSinkAdvice.class)
                                .on(namedOneOf("process", "processThrottled", "parseExpression"))))
                .installOn(instrumentation);

        // JSP/JSF Expression Language — the same SSTI shape through javax/jakarta EL.
        baseBuilder()
                .type(hasSuperType(named("javax.el.ExpressionFactory"))
                        .or(hasSuperType(named("jakarta.el.ExpressionFactory"))))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(GenericSinkAdvice.class)
                                .on(namedOneOf("createValueExpression", "createMethodExpression"))))
                .installOn(instrumentation);
    }

    // ④ GraphQL: the query document is attacker-controlled and drives resolver execution
    // (injection through arguments, introspection/batching abuse).
    private static void installGraphQlHooks(Instrumentation instrumentation) {
        baseBuilder()
                .type(named("graphql.GraphQL"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(GenericSinkAdvice.class)
                                .on(namedOneOf("execute", "executeAsync", "parseValidateAndExecute"))))
                .installOn(instrumentation);

        baseBuilder()
                .type(named("graphql.parser.Parser"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(GenericSinkAdvice.class)
                                .on(namedOneOf("parseDocument", "parse"))))
                .installOn(instrumentation);
    }

    // ---- Semantic (policy) RASP layer: authorization & race detection ----

    private static void installAuthzDecisionHooks(Instrumentation instrumentation) {
        // Every Spring Security authorization decision funnels through
        // AccessDecisionManager.decide — hook it to learn whether object-level
        // (ownership) authorization was enforced for the request.
        baseBuilder()
                .type(hasSuperType(named("org.springframework.security.access.AccessDecisionManager")))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(AuthzDecisionAdvice.class)
                                .on(named("decide").and(takesArguments(3)))))
                .installOn(instrumentation);

        // 注：MapperProxy.invoke 钩子（MyBatisReadAdvice）已停用——Executor.query 覆盖了它，
        // 且 MapperProxy 的代理类不实现 mapper 接口，实体名推导会退化成 "Unknown"，只产生噪声。
        // MyBatis 读统一由下面的 Executor.query 钩子采集。

        // Application principal source (custom login-state check instead of Spring
        // Security method security). Capture who is acting so the semantic layer can
        // name the accessor in a BOLA suspect event.
        baseBuilder()
                .type(named("com.sanjio.mall.security.CurrentUser"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(CurrentUserAdvice.class)
                                .on(named("of").and(takesArguments(1)))))
                .installOn(instrumentation);

        // Deepest MyBatis read funnel: every query (mapper interface OR native
        // SqlSession/Executor path used by SqlSessionFactoryBean) passes through
        // Executor.query. Hook it so object reads are captured regardless of which
        // MyBatis access style the app uses. The entity is derived from the
        // MappedStatement id (e.g. com.sanjio.mall.mapper.AddressMapper.findById).
        // 两种重载都要钩：CachingExecutor.query(ms, param, rowBounds, handler) 是入口，
        // 但它会委派给 delegate.query(ms, param, rowBounds, handler, cacheKey, boundSql)（6 参）。
        // 两者 arg0=MappedStatement / arg1=parameter，同一个 advice 可复用。
        baseBuilder()
                .type(hasSuperType(named("org.apache.ibatis.executor.Executor")))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(ExecutorQueryAdvice.class)
                                .on(named("query").and(takesArguments(4))))
                        .visit(Advice.to(ExecutorQueryAdvice.class)
                                .on(named("query").and(takesArguments(6)))))
                .installOn(instrumentation);
    }

    private static void installRepositoryReadHooks(Instrumentation instrumentation) {
        // Domain-object reads (findById) — feed BOLA correlation and race detection.
        // NOTE: CrudRepository.findById(ID) erases ID (bounded by Serializable) to
        // Serializable, so a type-constrained matcher like takesArgument(0, Object.class)
        // would NOT match. Match by name + arity only.
        baseBuilder()
                .type(hasSuperType(named("org.springframework.data.repository.CrudRepository")))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(RepositoryReadAdvice.class)
                                .on(named("findById").and(takesArguments(1)))))
                .installOn(instrumentation);
    }

    private static void installRepositoryWriteHooks(Instrumentation instrumentation) {
        // Domain-object writes (save / delete) — close the read-modify-write window.
        // Arity-only match: save/saveAndFlush/saveAll/delete/deleteById are all single-arg.
        baseBuilder()
                .type(hasSuperType(named("org.springframework.data.repository.CrudRepository")))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(RepositoryWriteAdvice.class)
                                .on(namedOneOf("save", "saveAndFlush", "saveAll", "delete", "deleteById")
                                        .and(takesArguments(1)))))
                .installOn(instrumentation);
    }

    private static void installConcurrencyHooks(Instrumentation instrumentation) {
        // @Transactional boundary.
        baseBuilder()
                .type(hasSuperType(named("org.springframework.transaction.interceptor.TransactionInterceptor")))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(TransactionAdvice.class)
                                .on(named("invoke").and(takesArguments(1)))))
                .installOn(instrumentation);

        // Explicit ReentrantLock acquire/release.
        baseBuilder()
                .type(named("java.util.concurrent.locks.ReentrantLock"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                        .visit(Advice.to(LockAdvice.class)
                                .on(namedOneOf("lock", "lockInterruptibly").and(takesArguments(0))))
                        .visit(Advice.to(LockAdvice.class)
                                .on(named("unlock").and(takesArguments(0)))))
                .installOn(instrumentation);
    }

    private static final class HookInstallListener implements AgentBuilder.Listener {
        @Override
        public void onDiscovery(String typeName, ClassLoader classLoader, JavaModule module, boolean loaded) {
        }

        @Override
        public void onTransformation(TypeDescription typeDescription, ClassLoader classLoader, JavaModule module,
                boolean loaded, DynamicType dynamicType) {
            AgentLogger.info("hook", "transformed " + typeDescription.getName());
            // A2 插桩覆盖台账：登记本类已成功织入。这是**静态安装态**（非"已触发态"）——
            // 后端 no-iast-evidence 归因靠它二分：「不在台账」= 探针没插到这条路径（观测缺失，
            // 不得判无漏洞）；「在台账」= 插到了但这次没触发（真漏报，重放要改）。
            // 早期方案曾想用「首次命中时登记」，但那样零事件请求的台账也是空的，二分失效，
            // 故必须挂在 onTransformation（织入成功即登记）。
            try {
                HookRuntime.registerInstalledHook(
                        "class|" + typeDescription.getName(),
                        "transformed@" + (classLoader == null ? "bootstrap" : classLoader.getClass().getSimpleName()));
            } catch (Throwable throwable) {
                AgentLogger.warn("hook", "hook inventory register failed-open: "
                        + throwable.getClass().getSimpleName());
            }
        }

        @Override
        public void onIgnored(TypeDescription typeDescription, ClassLoader classLoader, JavaModule module,
                boolean loaded) {
        }

        @Override
        public void onError(String typeName, ClassLoader classLoader, JavaModule module, boolean loaded,
                Throwable throwable) {
            AgentLogger.warn("hook", "failed-open transform " + typeName + ": " + throwable.getClass().getSimpleName()
                    + " - " + throwable.getMessage());
            // 织入失败也要落台账（带 failed 标记）：后端归因时能区分「压根没尝试插」
            // 与「尝试插了但失败」，二者都是观测缺失但根因不同。
            try {
                HookRuntime.registerInstalledHook("failed|" + typeName,
                        "error:" + throwable.getClass().getSimpleName());
            } catch (Throwable ignored) {
                // fail-open
            }
        }

        @Override
        public void onComplete(String typeName, ClassLoader classLoader, JavaModule module, boolean loaded) {
        }
    }
}
