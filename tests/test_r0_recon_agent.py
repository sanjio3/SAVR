import tempfile
import unittest
from pathlib import Path

from src.agents.r0_recon_agent import R0ReconAgent


class R0ReconAgentTests(unittest.TestCase):
    def test_scan_walks_project_without_recursive_self_call(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            (project / "pom.xml").write_text(
                "\n".join(
                    [
                        "<project>",
                        "  <dependencies>",
                        "    <dependency>org.springframework.boot:spring-boot-starter-web</dependency>",
                        "  </dependencies>",
                        "</project>",
                    ]
                ),
                encoding="utf-8",
            )
            (project / "src" / "main" / "java" / "com" / "demo").mkdir(parents=True)
            (project / "src" / "main" / "java" / "com" / "demo" / "DemoController.java").write_text(
                "\n".join(
                    [
                        "package demo;",
                        "import org.springframework.web.bind.annotation.GetMapping;",
                        "import org.springframework.web.bind.annotation.RestController;",
                        "@RestController",
                        "public class DemoController {",
                        '    @GetMapping("/health")',
                        "    public String health() {",
                        '        return "ok";',
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (project / "application.yml").write_text("server:\n  port: 8080\n", encoding="utf-8")

            agent = R0ReconAgent(str(project))
            info = agent.scan()

            self.assertEqual(info.name, project.name)
            self.assertGreaterEqual(len(info.http_routes), 1)
            self.assertTrue(any(route.get("path") == "/health" for route in info.http_routes))
            self.assertIn("application.yml", info.security_configs)
            self.assertEqual(info.framework, "spring")
            self.assertEqual(info.language, "java")


if __name__ == "__main__":
    unittest.main()
