import ipaddress
import os
import tempfile
import unittest

from asn_routes import (
    ASNData,
    Origin,
    build_route_lines,
    split_output_filename,
    split_route_lines,
    validate_and_write_output,
)


class OutputTests(unittest.TestCase):
    def test_routes_sort_by_numeric_ipv4(self):
        routes = {
            ipaddress.ip_network("100.0.0.0/8"): [Origin(1, "A")],
            ipaddress.ip_network("2.0.0.0/8"): [Origin(1, "A")],
            ipaddress.ip_network("10.0.0.0/8"): [Origin(1, "A")],
            ipaddress.ip_network("1.0.0.0/8"): [Origin(1, "A")],
        }
        lines = build_route_lines(routes, "0.0.0.0")
        self.assertEqual(
            [line.split()[2] for line in lines],
            ["1.0.0.0", "2.0.0.0", "10.0.0.0", "100.0.0.0"],
        )

    def test_route_comment_contains_only_asn_number(self):
        routes = {ipaddress.ip_network("1.0.0.0/8"): [Origin(12389, "ROSTELECOM-AS")]}
        self.assertEqual(
            build_route_lines(routes, "0.0.0.0"),
            ["route add 1.0.0.0 mask 255.0.0.0 0.0.0.0 & rem AS12389"],
        )

    def test_split_output_filename(self):
        self.assertEqual(split_output_filename("routes.dat", 0), "routes.dat")
        self.assertEqual(split_output_filename("routes.dat", 1), "routes(1).dat")
        self.assertEqual(split_output_filename("out/routes.dat", 2), "out/routes(2).dat")

    def test_split_route_lines_by_1024(self):
        chunks = split_route_lines([str(index) for index in range(2050)], 1024)
        self.assertEqual([len(chunk) for chunk in chunks], [1024, 1024, 2])

    def test_validate_and_write_output_splits_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "routes.dat")
            lines = [
                f"route add 10.{first}.{second}.0 mask 255.255.255.0 0.0.0.0 & rem AS64500"
                for first in range(9)
                for second in range(256)
            ][:2050]
            files = validate_and_write_output(
                lines,
                path,
                gateway="0.0.0.0",
                asn_data=[ASNData(64500, status="ok")],
                max_lines=1024,
            )
            self.assertEqual(files, [path, os.path.join(tmpdir, "routes(1).dat"), os.path.join(tmpdir, "routes(2).dat")])
            line_counts = []
            for file_path in files:
                with open(file_path, "r", encoding="utf-8") as handle:
                    line_counts.append(len(handle.read().splitlines()))
            self.assertEqual(
                line_counts,
                [1024, 1024, 2],
            )

    def test_invalid_output_does_not_replace_existing_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "routes.dat")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("original\n")
            with self.assertRaises(Exception):
                validate_and_write_output([], path, gateway="0.0.0.0", asn_data=[ASNData(1, status="ok")])
            with open(path, "r", encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "original\n")


if __name__ == "__main__":
    unittest.main()
