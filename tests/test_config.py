import os
import tempfile
import unittest
from pathlib import Path

from src.core.config import Config


class ConfigTests(unittest.TestCase):
    def test_env_var_expansion_and_api_aggregation(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            config_path.write_text(
                "\n".join(
                    [
                        "qwen:",
                        "  api_key: \"${TEST_QWEN_KEY}\"",
                        "api:",
                        "  provider: \"qwen\"",
                    ]
                ),
                encoding="utf-8",
            )
            os.environ["TEST_QWEN_KEY"] = "secret-value"
            try:
                cfg = Config()
                cfg.load(str(config_path))
                self.assertEqual(cfg.get("qwen.api_key"), "secret-value")
                aggregated = cfg.get("api")
                self.assertEqual(aggregated["provider"], "qwen")
                self.assertEqual(aggregated["qwen"]["api_key"], "secret-value")
            finally:
                os.environ.pop("TEST_QWEN_KEY", None)


if __name__ == "__main__":
    unittest.main()
