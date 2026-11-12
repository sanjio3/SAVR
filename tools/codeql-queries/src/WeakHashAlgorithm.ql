/**
 * @name 使用已被攻破的弱哈希算法（CWE-328）
 * @description 调用 MessageDigest.getInstance("MD5"/"SHA-1") 或 commons-codec / Guava /
 *              Spring DigestUtils 的 md5、sha1 系列便捷方法。这些算法已被碰撞攻击攻破，
 *              不可用于安全用途。官方 java-queries 的 Security/CWE/CWE-328 目录为空，
 *              本查询用于补齐该类别。
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision high
 * @id sastai/java/weak-hash-algorithm
 * @tags security
 *       external/cwe/cwe-328
 */

import java

/** MD5 / SHA-1 / SHA-0 等已攻破摘要算法的名称特征。 */
bindingset[name]
private predicate isWeakDigestName(string name) {
  name.regexpMatch("(?i).*(^|[^a-z0-9])(md5|md2|md4|sha-?0|sha-?1)([^a-z0-9]|$).*")
}

/** commons-codec / Guava / Spring 封装的弱摘要便捷方法。 */
private class WeakDigestHelperCall extends MethodCall {
  WeakDigestHelperCall() {
    exists(string pkg, string cls, string m |
      this.getMethod().hasQualifiedName(pkg, cls, m) and
      (
        pkg = "org.apache.commons.codec.digest" and cls = "DigestUtils"
        or
        pkg = "com.google.common.hash" and cls = "Hashing"
        or
        pkg = "org.springframework.util" and cls = "DigestUtils"
      ) and
      isWeakDigestName(m)
    )
  }
}

from Expr e, string why
where
  exists(MethodCall mc, Expr arg |
    mc.getMethod().hasQualifiedName("java.security", "MessageDigest", "getInstance") and
    arg = mc.getArgument(0) and
    isWeakDigestName(arg.(CompileTimeConstantExpr).getStringValue()) and
    e = mc and
    why = "MessageDigest.getInstance 使用了已被攻破的摘要算法"
  )
  or
  (e instanceof WeakDigestHelperCall and why = "调用了弱摘要便捷方法")
select e, why
