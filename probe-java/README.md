# probe-java（项目内置 IAST/RASP 探针）

本目录是 SAVR 内置的 IAST/RASP 探针 Java 源码，使本项目成为可独立构建、独立运行的完整项目。
在此之前探针源码位于 SAVR 之外的另一个本机仓库，
项目只能依赖一个外部绝对路径才能跑起来，不是自洽的工程。

## 目录说明

src/main/java/com/rasp/probe 探针主体（污点追踪、熔断、上报、字节码插桩）。
src/test/java 探针单元测试（含 TaintHubConcurrencyTest 并发锁回归）。
pom.xml Maven 构建描述。

## 构建

在项目根目录执行（JDK 11，注意 Windows 上 jar 工具不认 --create/--file）：

```
C:\apache-maven-3.9.11\bin\mvn.cmd -B -DskipTests -f probe-java/pom.xml clean package
```

产物为 probe-java/target/sec-probe.jar。构建前必须先停靶场 JVM，否则 jar 被占用无法覆盖。

bootstrap 片段（供 -Xbootclasspath/a 使用，须与主 jar 同一套 class 版本）：

```
jar cf probe-java/target/sec-probe-bootstrap.jar -C probe-java/target/classes com/rasp/probe/TaintHub.class
```

## 启动脚本如何使用

launch_target_mall.py / launch_java_seccode.py / launch_java_quote.py 里的 PROBE 变量优先取项目内
probe-java/target/sec-probe.jar；找不到时回退到外部 IAST_RASP 路径，保证过渡期两处都能跑。
因此只要在本项目内构建过，启动靶场就整套自洽，不再依赖 SAVR 之外的任何目录。

## 与外部 IAST_RASP 的关系

本目录是源码副本，来源与同步方式见 MANIFEST.md。探针的独立研发仍在 IAST_RASP 进行时，
应在本目录重新同步并重建 jar，避免两边源码漂移。
