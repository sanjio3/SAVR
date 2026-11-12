# probe-java — IAST / RASP 探针

本目录是 SAVR 的进程内探针源码：污点追踪、字节码插桩、事件上报与熔断。它是「确认」这一步
的物理基础——静态分析和 LLM 只能提出候选，真正证明漏洞成立的是探针在 sink 上捕捉到的
事件。源码随仓库分发，构建产物不分发。

## 目录

- `src/main/java/com/rasp/probe`：探针主体（ByteBuddy 插桩、污点汇聚、上报、熔断）
- `src/test/java`：探针单元测试，含 TaintHub 并发锁回归
- `pom.xml`：Maven 构建描述

## 构建

需要 JDK 11 与 Maven，在仓库根目录执行：

```bash
mvn -B -DskipTests -f probe-java/pom.xml clean package
jar cf probe-java/target/sec-probe-bootstrap.jar -C probe-java/target/classes com/rasp/probe/TaintHub.class
```

第一条产出 `probe-java/target/sec-probe.jar`，第二条产出
`probe-java/target/sec-probe-bootstrap.jar`。bootstrap 只含 `TaintHub` 一个类，必须放进
`-Xbootclasspath/a` —— 探针要在 JDK 类加载器启动之前就能看到它，否则 bootstrap 期的插桩
拿不到共享状态。**两条都要跑，Maven 不会自动生成 bootstrap jar。**

两个 jar 必须来自同一次构建，class 版本才一致。构建前先停掉靶场 JVM，否则 jar 被占用无法
覆盖。Windows 上的 `jar` 工具不认 `--create` / `--file` 长选项，用上面的短选项形式。

## 挂载

完整参数、四个必须核对的点（业务包前缀、`127.0.0.1`、token 一致性、启动前挂载）与自检命令，
见仓库根目录 `README.md` 的「构建探针」一节。最简形式：

```bash
java -Xbootclasspath/a:probe-java/target/sec-probe-bootstrap.jar \
     -javaagent:probe-java/target/sec-probe.jar \
     -Dsec.server.url=http://127.0.0.1:8000 \
     -Dsec.agent.id=<agent-id> \
     -Dsec.app.name=<app-name> \
     -Dsec.agent.token=<database probe_token> \
     -Dsec.app.packages=<your business package prefix> \
     -jar your-target.jar
```

`scripts/launch/launch_java_quote.py` 是可直接照抄的完整示例。

## 探针接入后的自检

```bash
python tools/probe_preflight.py --workspace-id <id> --http
```

`ready=true` 表示会话行存在、心跳新鲜、`X-Agent-Token` 握手被接受且返回非空 `session_id`。
探针没接上时，摄取接口仍然返回 HTTP 200 且 `accepted=0`，看起来像成功——这是最容易误判的
一种失败。
