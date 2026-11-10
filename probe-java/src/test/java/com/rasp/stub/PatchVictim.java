package com.rasp.stub;

/**
 * 方法级虚拟补丁的验证靶类 (手册 11.2.5)。
 *
 * <p>刻意放在 {@code com.rasp.stub}：{@code baseBuilder()} 的 ignore 列表含
 * {@code com.rasp.probe.}，桩类若放探针包内会被直接忽略、永不织入。
 *
 * <p>刻意<b>非 final</b>：{@code VirtualPatchRegistry.rejectReason(Class)} 按手册
 * 11.2.5 二拒绝 final 类的 retransform。
 */
public class PatchVictim {
    /** 被 CVE 波及的方法：虚拟补丁的目标。 */
    public String vulnerable(String payload) {
        return "vulnerable:" + payload;
    }

    /** 同类内的无关方法：必须证明补丁不会溢出到它身上。 */
    public String untouched(String payload) {
        return "untouched:" + payload;
    }
}
