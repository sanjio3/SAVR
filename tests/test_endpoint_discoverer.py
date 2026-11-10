import unittest

from src.core.endpoint_discoverer import EndpointDiscoverer, extract_endpoints_from_files


class EndpointDiscovererTests(unittest.TestCase):
    def setUp(self):
        self.discoverer = EndpointDiscoverer()

    def test_extract_java_params_supports_annotation_variants(self):
        lines = [
            '    public String update(',
            '        @RequestParam("id") final String userId,',
            '        @RequestParam(name = "q", required = false) String keyword,',
            '        @PathVariable(value = "slug") String articleSlug,',
            '        @RequestBody Map<String, Object> body,',
            '        HttpServletRequest request,',
            '        BindingResult bindingResult,',
            '        @RequestParam String[] tags',
            '    ) {',
            '        return "ok";',
            '    }',
        ]

        params = self.discoverer._extract_java_params(lines, 0)

        self.assertEqual(
            params,
            [
                {
                    "name": "userId",
                    "type": "String",
                    "annotation": "RequestParam",
                    "source_name": "id",
                },
                {
                    "name": "keyword",
                    "type": "String",
                    "annotation": "RequestParam",
                    "source_name": "q",
                },
                {
                    "name": "articleSlug",
                    "type": "String",
                    "annotation": "PathVariable",
                    "source_name": "slug",
                },
                {
                    "name": "body",
                    "type": "Map<String, Object>",
                    "annotation": "RequestBody",
                },
                {
                    "name": "tags",
                    "type": "String[]",
                    "annotation": "RequestParam",
                },
            ],
        )

    def test_discover_java_endpoints_keeps_class_mapping_and_multiline_params(self):
        content = """
package demo;

import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class DemoController {

    @GetMapping("/quote/{slug}")
    public Map<String, Object> loadQuote(
        @PathVariable("slug") String quoteSlug,
        @RequestParam(name = "expand", required = false) List<String> expand,
        @RequestBody Map<String, Object> payload
    ) {
        return payload;
    }
}
""".strip()

        endpoints = self.discoverer.discover_from_file(
            content,
            "DemoController.java",
            "src/main/java/demo/DemoController.java",
        )

        self.assertEqual(len(endpoints), 1)
        endpoint = endpoints[0]
        self.assertEqual(endpoint["path"], "/api/quote/{slug}")
        self.assertEqual(endpoint["method"], "GET")
        self.assertEqual(
            endpoint["params"],
            [
                {
                    "name": "quoteSlug",
                    "type": "String",
                    "annotation": "PathVariable",
                    "source_name": "slug",
                },
                {
                    "name": "expand",
                    "type": "List<String>",
                    "annotation": "RequestParam",
                    "source_name": "expand",
                },
                {
                    "name": "payload",
                    "type": "Map<String, Object>",
                    "annotation": "RequestBody",
                },
            ],
        )

    def test_extract_endpoints_from_files_uses_debug_controller_request_param(self):
        content = """
package com.quote.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DebugController {

    @PostMapping("/debug/import")
    public String importConfig(@RequestParam String data) {
        return data;
    }
}
""".strip()

        endpoints = extract_endpoints_from_files(
            [
                {
                    "name": "DebugController.java",
                    "rel_path": "src/main/java/com/quote/controller/DebugController.java",
                    "content": content,
                }
            ]
        )

        debug_endpoints = endpoints["src/main/java/com/quote/controller/DebugController.java"]
        self.assertEqual(len(debug_endpoints), 1)
        self.assertEqual(debug_endpoints[0]["path"], "/debug/import")
        self.assertEqual(
            debug_endpoints[0]["params"],
            [{"name": "data", "type": "String", "annotation": "RequestParam"}],
        )

    def test_discovers_hono_typescript_routes(self):
        content = """
import { Hono } from 'hono'

const app = new Hono()
app.post('/eval', async (c) => {
    const code = await c.req.text()
    return c.json({ code })
})
""".strip()

        endpoints = self.discoverer.discover_from_file(content, "app.tsx", "app.tsx")

        self.assertEqual(len(endpoints), 1)
        self.assertEqual(endpoints[0]["path"], "/eval")
        self.assertEqual(endpoints[0]["method"], "POST")

    def test_discovers_wordpress_register_rest_route(self):
        content = """
class FlushLogs {
    protected $endpoint = 'logs/flush-logs';

    public function registerRoute()
    {
        register_rest_route(
            'give-api/v2',
            $this->endpoint,
            [
                [
                    'methods' => 'DELETE',
                    'callback' => [$this, 'handleRequest'],
                ],
            ]
        );
    }
}
""".strip()

        endpoints = self.discoverer.discover_from_file(content, "FlushLogs.php", "src/API/Endpoints/Logs/FlushLogs.php")

        self.assertEqual(len(endpoints), 1)
        self.assertEqual(endpoints[0]["path"], "/wp-json/give-api/v2/logs/flush-logs")
        self.assertEqual(endpoints[0]["method"], "DELETE")


if __name__ == "__main__":
    unittest.main()
