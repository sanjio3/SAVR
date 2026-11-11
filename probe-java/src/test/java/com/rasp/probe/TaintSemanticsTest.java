package com.rasp.probe;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Regression cover for the L2 taint semantics added in this suite, and
 * each test pins down a behaviour that was previously either missing or
 * outright wrong (blanket un-taint on sanitize, no request-scoped cleanup, no carrier or
 * array inheritance), so a future refactor cannot silently regress them.
 */
class TaintSemanticsTest {

    @AfterEach
    void cleanup() {
        TaintStore.clearCurrentRequest();
    }

    // ---- requestId 归集 / 清理 ----

    @Test
    void requestShadowIsCollectedUnderRequestIdAndDroppedOnExit() {
        TaintStore.bindRequest("req-1");
        assertEquals("req-1", TaintStore.currentRequestId());

        TaintStore.markHigh("tainted-order-id");
        assertTrue(TaintStore.isContentTainted("select * from t where id='tainted-order-id'"),
                "content shadow must recognize a derived string by containment");
        assertEquals(1, TaintStore.liveRequestShadowCount());

        TaintStore.clearCurrentRequest();
        assertEquals(0, TaintStore.liveRequestShadowCount(), "exitRequest must drop the whole request shadow");
        assertFalse(TaintStore.isRequestTainted());
        assertFalse(TaintStore.isContentTainted("select * from t where id='tainted-order-id'"),
                "a value that outlived its request must not look tainted to the next request");
    }

    @Test
    void pooledThreadInheritsOriginatingRequestShadow() throws Exception {
        TaintStore.bindRequest("req-async");
        TaintStore.markHigh("cross-thread-secret");

        AtomicBoolean seenBeforeBind = new AtomicBoolean(true);
        AtomicBoolean seenAfterBind = new AtomicBoolean(false);
        Thread worker = new Thread(() -> {
            // a fresh pool thread starts clean …
            seenBeforeBind.set(TaintStore.isContentTainted("x cross-thread-secret y"));
            // … and inherits the request shadow once it adopts the request scope
            TaintStore.bindRequest("req-async");
            seenAfterBind.set(TaintStore.isContentTainted("x cross-thread-secret y")
                    && TaintStore.isRequestTainted());
            TaintStore.detachThread();
        });
        worker.start();
        worker.join();

        assertFalse(seenBeforeBind.get(), "an unbound thread must not see another request's shadow");
        assertTrue(seenAfterBind.get(), "bindRequest must re-raise the flag and adopt the shadow");
        // detachThread must NOT drop the shadow — the originating request is still running.
        assertEquals(1, TaintStore.liveRequestShadowCount());
        assertTrue(TaintStore.isContentTainted("x cross-thread-secret y"));
    }

    // ---- byte[] / char[] 边界继承 ----

    @Test
    void carrierSourceMarksArrayAndRegistersDecodedContent() {
        TaintStore.bindRequest("req-carrier");
        byte[] body = "payload-from-body".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        TaintStore.markHighCarrier(body);

        assertTrue(TaintStore.isHigh(body), "the carrier itself must be marked");
        // new String(bytes) can never be hooked (String is primordial) — the decoded content
        // shadow is the only thing that keeps the derived String recognizable.
        assertTrue(TaintStore.isContentTainted("cmd " + new String(body, java.nio.charset.StandardCharsets.UTF_8)),
                "decoded carrier content must be registered in the shadow");

        char[] chars = "chars-from-reader".toCharArray();
        TaintStore.markHighCarrier(chars);
        assertTrue(TaintStore.isHigh(chars));
        assertTrue(TaintStore.isContentTainted("prefix " + new String(chars)));
    }

    // ---- 数组重组 ----

    @Test
    void arrayReorganisationInheritsElementTaint() {
        TaintStore.bindRequest("req-array");
        String element = "tainted-element";
        TaintStore.markHigh(element);

        Object[] source = {"clean", element};
        Object[] copy = Arrays.copyOf(source, source.length);
        TaintStore.markArrayFrom(copy, source);

        assertTrue(TaintStore.isHigh(copy[1]), "per-element marks must be carried over");
        assertTrue(TaintStore.isHigh(copy), "the destination array itself must carry taint for the deep scan");
    }

    @Test
    void carrierArrayCopyInheritsThroughContentShadow() {
        TaintStore.bindRequest("req-array-carrier");
        byte[] body = "buffer-payload".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        TaintStore.markHighCarrier(body);

        byte[] trimmed = Arrays.copyOf(body, body.length);
        TaintStore.markArrayFrom(trimmed, body);
        assertTrue(TaintStore.isHigh(trimmed), "a resized request buffer must stay tainted");
    }

    // ---- 净化器分治 ----

    @Test
    void htmlSanitizerDoesNotDefuseSqlSink() {
        TaintStore.bindRequest("req-sanitize");
        String escaped = "escaped&lt;value&gt;";
        TaintStore.markHigh(escaped);
        String origin = "org.springframework.web.util.HtmlUtils.htmlEscape";
        TaintStore.markSanitized(escaped, origin, TaintStore.familiesForSanitizer(origin));

        assertTrue(TaintStore.isSanitizedFor(escaped, TaintStore.FAMILY_HTML));
        assertFalse(TaintStore.isSanitizedFor(escaped, TaintStore.FAMILY_SQL),
                "HTML escaping must NOT defuse a SQL sink — that bypass is the whole point of 分治");
        assertTrue(TaintStore.isHigh(escaped), "a sanitizer must not blanket-erase the taint mark");
        assertTrue(TaintStore.sanitizerOf(escaped).startsWith(origin), "sanitizer identity must stay traceable");
    }

    @Test
    void unknownSanitizerDefusesNothing() {
        assertEquals("", TaintStore.familiesForSanitizer("com.acme.Util.scrub"),
                "an unrecognized sanitizer must defuse no family (safe default)");
    }

    @Test
    void taintGateSkipsOnlyTheSanitizedFamily() {
        TaintStore.bindRequest("req-gate");
        String escaped = "1' or '1'='1";
        TaintStore.markHigh(escaped);
        String origin = "org.springframework.web.util.HtmlUtils.htmlEscape";
        TaintStore.markSanitized(escaped, origin, TaintStore.familiesForSanitizer(origin));

        Object[] args = {escaped};
        assertTrue(TaintGate.hasHighTaint("com.mysql.cj.jdbc.ClientPreparedStatement.executeQuery", args),
                "an HTML-escaped value must still be taint-blockable at a SQL sink");
        assertFalse(TaintGate.hasHighTaint("org.thymeleaf.TemplateEngine.process", args),
                "the sink family the sanitizer actually neutralizes must be skipped");
    }

    // ---- 盲点家族分类 ----

    @Test
    void blindSpotSinksAreClassifiedDangerous() {
        assertTrue(TaintGate.isDangerous("com.fasterxml.jackson.databind.ObjectMapper.readValue"));
        assertTrue(TaintGate.isDangerous("com.mongodb.client.internal.MongoCollectionImpl.find"));
        assertTrue(TaintGate.isDangerous("freemarker.template.Template.process"));
        assertTrue(TaintGate.isDangerous("graphql.GraphQL.execute"));
        assertTrue(TaintGate.isDangerous("org.yaml.snakeyaml.Yaml.load"));
        assertFalse(TaintGate.isDangerous("com.acme.service.OrderService.list"));
    }

    @Test
    void sinkFamilyMappingCoversNewFamilies() {
        assertEquals(TaintStore.FAMILY_SQL,
                TaintGate.familyOf("com.zaxxer.hikari.pool.HikariProxyStatement.executeQuery"));
        assertEquals(TaintStore.FAMILY_JSON,
                TaintGate.familyOf("com.fasterxml.jackson.databind.ObjectMapper.readValue"));
        assertEquals(TaintStore.FAMILY_HTML, TaintGate.familyOf("freemarker.template.Template.process"));
        assertEquals(TaintStore.FAMILY_SHELL, TaintGate.familyOf("java.lang.Runtime.exec"));
    }

    // ---- 字段级污点 ----

    @Test
    void fieldWriteTaintsContainerAndRecordsFieldName() {
        TaintStore.bindRequest("req-field");
        Object dto = new Object();
        String value = "tainted-field-value";
        TaintStore.markHigh(value);

        TaintStore.markFieldTaint(dto, "orderId", value);
        assertTrue(TaintStore.isHigh(dto), "a DTO holding user input must itself be tainted");
        assertTrue(TaintStore.hasFieldTaint(dto));
        assertTrue(TaintStore.isFieldTainted(dto, "orderId"));
        assertFalse(TaintStore.isFieldTainted(dto, "customerId"));
    }

    @Test
    void fieldReadOfTaintedContainerYieldsTaintedValue() {
        TaintStore.bindRequest("req-field-read");
        Object dto = new Object();
        TaintStore.markHigh(dto);
        String readBack = "value-read-back";

        TaintStore.propagateFieldRead(dto, null, readBack);
        assertTrue(TaintStore.isHigh(readBack), "pulling a value out of a tainted container must taint it");
    }

    // ---- 参数化查询感知 ----

    @Test
    void parameterizedQueryWithTaintedParameterIsNotTreatedAsInjection() {
        TaintStore.bindRequest("req-prepared");
        String template = "select * from orders where id = ?";
        String attackParameter = "1' or '1'='1";
        TaintStore.markHigh(attackParameter);

        Object statement = new Object();
        HookRuntime.rememberPreparedSql(statement, template);
        HookRuntime.rememberPreparedParameter(statement, 1, attackParameter);

        // The static template must stay clean: nothing here may throw (block) and the
        // signature layer must never see the bound parameter value.
        HookRuntime.onPreparedSink("com.mysql.cj.jdbc.ClientPreparedStatement.executeQuery", statement);
        assertFalse(TaintStore.isContentTainted(template),
                "a static template must not be considered tainted just because a parameter is");
    }

    @Test
    void concatenatedTemplateIsStillSeenAsTainted() {
        TaintStore.bindRequest("req-concat");
        String userInput = "1 or 1=1";
        TaintStore.markHigh(userInput);
        String template = "select * from orders where id = " + userInput;

        assertTrue(TaintStore.isContentTainted(template),
                "a template built by concatenation must remain recognizable as tainted");
    }
}
