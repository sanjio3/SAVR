import unittest

from src.infrastructure.db import Database


class DatabaseJsonTests(unittest.TestCase):
    def test_loads_null_json_as_empty_dict(self):
        self.assertEqual(Database.loads("null"), {})


if __name__ == "__main__":
    unittest.main()
