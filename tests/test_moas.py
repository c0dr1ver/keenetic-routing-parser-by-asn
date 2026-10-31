import ipaddress
import unittest

from asn_routes import ASNData, build_route_lines, merge_exact_moas


class MOASTests(unittest.TestCase):
    def test_exact_duplicate_prefixes_merge_to_one_route(self):
        data = [
            ASNData(
                asn=100,
                name="NAME-A",
                aggregated_prefixes=[ipaddress.ip_network("1.2.0.0/16")],
            ),
            ASNData(
                asn=200,
                name="NAME-B",
                aggregated_prefixes=[ipaddress.ip_network("1.2.0.0/16")],
            ),
        ]
        routes, merged = merge_exact_moas(data)
        lines = build_route_lines(routes, "0.0.0.0")
        self.assertEqual(merged, 1)
        self.assertEqual(
            lines,
            ["route add 1.2.0.0 mask 255.255.0.0 0.0.0.0 & rem AS100, AS200"],
        )


if __name__ == "__main__":
    unittest.main()
