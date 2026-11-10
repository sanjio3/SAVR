# 探针源码来源与同步清单

## 来源

外部原始路径：并入前位于本机另一个独立仓库（路径因部署环境而异，未随本项目分发）
并入日期：2026-09-14
并入方式：复制 src/ 与 pom.xml（未复制 target/、jar、logs、构建日志，这些属产物不含源码）

## 源码指纹

算法：对 probe-java/src 下全部 .java 按相对路径排序后，依次哈希「相对路径 + 文件内容」，取 SHA-256。

并入时指纹：5f996899639f37ae7673b400b0b1b984f5d07c48c03d6e914e0361c8839a4c4a
文件数：128

并入当时与外部源码逐字节一致（同一指纹）。此后若两边任一改动，指纹即不同。

## 如何校验是否漂移

在项目根目录执行（对内置与外部各算一次指纹并比对；把 `<external-probe-root>` 换成你本地那份外部探针源码路径）：

```
.venv/Scripts/python.exe -c "import hashlib,os;fp=lambda r:hashlib.sha256(b''.join(os.path.relpath(os.path.join(d,f),r).replace(chr(92),'/').encode()+open(os.path.join(d,f),'rb').read() for d,_,fs in os.walk(r) for f in sorted(fs) if f.endswith('.java'))).hexdigest();print('内置',fp('probe-java/src'));print('外部',fp('<external-probe-root>/src'))"
```

两行 hash 相同即未漂移；不同则说明有一侧被改动，需决定以哪侧为准并同步。

## 同步约定

以哪边为准由用户决定。若继续在 IAST_RASP 研发探针，则每轮研发后把
IAST_RASP/probe-java/src 覆盖到本目录并更新上面的指纹；若反过来以本项目为准，
则 IAST_RASP 侧改为指向本项目。禁止两边各自改动而不合并。
