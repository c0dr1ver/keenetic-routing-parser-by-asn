import unittest

from asn_routes import ConfigError, parse_asn_list


class ASNParsingTests(unittest.TestCase):
    def test_parse_plain_list(self):
        self.assertEqual(parse_asn_list("3216,6697,12389"), [3216, 6697, 12389])

    def test_parse_deduplicates_preserving_order(self):
        self.assertEqual(parse_asn_list("3216, 6697, 3216"), [3216, 6697])

    def test_parse_rejects_non_numeric(self):
        with self.assertRaises(ConfigError):
            parse_asn_list("3216,abc")


if __name__ == "__main__":
    unittest.main()
