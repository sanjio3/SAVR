package com.rasp.probe;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.RandomAccessFile;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 2026-09-16（待请示 6 项 #4）：sec-agent.log 按大小轮转的回归测试。
 *
 * <p>轮转是纯磁盘保护逻辑，正常运行时要等单文件涨到 64MB 才触发，靠跑全量扫描验证不现实
 * （新日志从 0 起步，几小时内到不了阈值）。故这里直接把单例的 {@code file} 指到临时目录、
 * 用反射调用私有的 {@code append}/{@code rotate}，在毫秒级内复现「超限→轮转→保留 3 份」。
 *
 * <p>只读 local logger 自身的私有成员，不改动任何生产代码可见性。
 */
class LocalEventLoggerRotationTest {

    /** 与 LocalEventLogger.MAX_FILE_BYTES 对齐（单文件上限）。 */
    private static final long MAX_FILE_BYTES = 64L * 1024 * 1024;
    /** 与 LocalEventLogger.MAX_BACKUPS 对齐（备份份数）。 */
    private static final int MAX_BACKUPS = 3;

    @TempDir
    Path tmp;

    private Object originalFile;

    @BeforeEach
    void captureOriginalTarget() throws Exception {
        this.originalFile = fileField().get(logger());
    }

    @AfterEach
    void restoreOriginalTarget() throws Exception {
        fileField().set(logger(), originalFile);
    }

    @Test
    void rotatesCascadeAndKeepsThreeBackups() throws Exception {
        Path log = tmp.resolve("sec-agent.log");
        write(log, "current");
        write(tmp.resolve("sec-agent.log.1"), "backup-1");
        write(tmp.resolve("sec-agent.log.2"), "backup-2");
        write(tmp.resolve("sec-agent.log.3"), "oldest");

        retarget(log);
        rotate();

        // current → .1，.1 → .2，.2 → .3，最旧的 .3 被覆盖丢弃
        assertEquals("current", read(tmp.resolve("sec-agent.log.1")));
        assertEquals("backup-1", read(tmp.resolve("sec-agent.log.2")));
        assertEquals("backup-2", read(tmp.resolve("sec-agent.log.3")));
        // 轮转是「移动」，原文件不再存在，append 会重建
        assertFalse(Files.exists(log), "轮转后原文件应已被移走，等待下次写入重建");
        // 备份份数不溢出
        assertFalse(Files.exists(tmp.resolve("sec-agent.log." + (MAX_BACKUPS + 1))),
                "备份份数不得超过 MAX_BACKUPS");
    }

    @Test
    void appendRotatesWhenSizeLimitWouldBeExceeded() throws Exception {
        Path log = tmp.resolve("sec-agent.log");
        // 稀疏文件：setLength 瞬间把大小顶到阈值，避免真的写 64MB
        try (RandomAccessFile raf = new RandomAccessFile(log.toFile(), "rw")) {
            raf.setLength(MAX_FILE_BYTES);
        }
        assertTrue(Files.size(log) >= MAX_FILE_BYTES);

        retarget(log);
        append("after-rotation\n");

        assertEquals("after-rotation\n", read(log), "新文件应只含轮转后的内容");
        assertEquals(MAX_FILE_BYTES, Files.size(tmp.resolve("sec-agent.log.1")),
                "旧内容应整体落到 .1");
    }

    @Test
    void appendDoesNotRotateBelowSizeLimit() throws Exception {
        Path log = tmp.resolve("sec-agent.log");
        write(log, "small");
        retarget(log);
        append("-more");

        assertEquals("small-more", read(log));
        assertFalse(Files.exists(tmp.resolve("sec-agent.log.1")), "未超限不应产生备份");
    }

    @Test
    void rotateIsBestEffortWhenTargetMissing() throws Exception {
        // file 指向不存在的目录下的文件：轮转必须静默失败，绝不抛入热路径
        retarget(tmp.resolve("no-such-dir").resolve("sec-agent.log"));
        assertDoesNotThrow(this::rotate);
    }

    // ---- 反射辅助：只读私有成员，零生产代码改动 ----

    private Object logger() throws Exception {
        return LocalEventLogger.instance();
    }

    private static Field fileField() throws Exception {
        Field f = LocalEventLogger.class.getDeclaredField("file");
        f.setAccessible(true);
        return f;
    }

    private void retarget(Path file) throws Exception {
        fileField().set(logger(), file);
    }

    private void append(String text) throws Exception {
        Method m = LocalEventLogger.class.getDeclaredMethod("append", String.class);
        m.setAccessible(true);
        try {
            m.invoke(logger(), text);
        } catch (InvocationTargetException e) {
            throw (Exception) e.getCause();
        }
    }

    private void rotate() throws Exception {
        Method m = LocalEventLogger.class.getDeclaredMethod("rotate");
        m.setAccessible(true);
        try {
            m.invoke(logger());
        } catch (InvocationTargetException e) {
            throw (Exception) e.getCause();
        }
    }

    private static void write(Path p, String content) throws Exception {
        Files.write(p, content.getBytes(StandardCharsets.UTF_8));
    }

    private static String read(Path p) throws Exception {
        return Files.readString(p, StandardCharsets.UTF_8);
    }
}
