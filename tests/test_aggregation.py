import ipaddress
import unittest

from asn_routes import ASNData, aggregate_prefixes


def networks(values):
    return [ipaddress.ip_network(value) for value in values]


class AggregationTests(unittest.TestCase):
    def test_adjacent_24s_become_23(self):
        result = aggregate_prefixes(networks(["1.0.0.0/24", "1.0.1.0/24"]))
        self.assertEqual([str(item) for item in result], ["1.0.0.0/23"])

    def test_recursive_aggregation(self):
        result = aggregate_prefixes(
            networks(["1.0.0.0/24", "1.0.1.0/24", "1.0.2.0/24", "1.0.3.0/24"])
        )
        self.assertEqual([str(item) for item in result], ["1.0.0.0/22"])

    def test_nested_networks_removed(self):
        result = aggregate_prefixes(networks(["1.0.0.0/16", "1.0.1.0/24", "1.0.2.0/24"]))
        self.assertEqual([str(item) for item in result], ["1.0.0.0/16"])

    def test_different_asns_are_not_aggregated_together(self):
        as100 = ASNData(100, prefixes=networks(["1.0.0.0/24"]))
        as200 = ASNData(200, prefixes=networks(["1.0.1.0/24"]))
        as100.aggregated_prefixes = aggregate_prefixes(as100.prefixes)
        as200.aggregated_prefixes = aggregate_prefixes(as200.prefixes)
        self.assertEqual([str(item) for item in as100.aggregated_prefixes], ["1.0.0.0/24"])
        self.assertEqual([str(item) for item in as200.aggregated_prefixes], ["1.0.1.0/24"])


if __name__ == "__main__":
    unittest.main()
