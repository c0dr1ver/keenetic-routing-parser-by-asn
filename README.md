# Keenetic Routing Parser by ASN

Generate `route add` command files from current IPv4 BGP prefixes originated by a configured list of ASNs.

The project is a standalone Python 3 script. It queries RIPE RISwhois over TCP/43, validates and aggregates IPv4 prefixes per ASN, merges exact MOAS duplicates, sorts routes numerically, and writes Windows-compatible `.dat` files.

## Features

- Uses only the Python standard library.
- Reads ASN values from one comma-separated configuration string.
- Queries RIPE RISwhois (`riswhois.ripe.net:43`) with `!gAS<ASN>`.
- Uses persistent IRRd multi-command mode (`!!`) instead of opening one TCP connection per ASN.
- Parses IRRd-style framed responses as a stream.
- Shows progress, elapsed time, retry warnings, and final statistics.
- Validates IPv4 prefixes with `ipaddress`.
- Deduplicates prefixes inside each ASN.
- Aggregates adjacent and nested CIDR networks per ASN with `ipaddress.collapse_addresses()`.
- Does not aggregate prefixes from different ASNs together.
- Merges exact duplicate MOAS routes into one command.
- Sorts output by numeric IPv4 address.
- Converts CIDR prefix length to dotted-decimal netmask automatically.
- Writes output atomically via temporary files and `os.replace()`.
- Splits output into multiple `.dat` files when the route count exceeds 1024 lines.
- Includes unit tests based on `unittest`.

## Requirements

- Python 3.10 or newer.
- Network access to `riswhois.ripe.net` on TCP port `43`.
- No `pip install` dependencies are required.

## Quick Start

Edit the configuration section at the top of `asn_routes.py`:

```python
ASN_LIST = "3216,6697,6764,8901,12389"
OUTPUT_FILE = "ruroutes.dat"
GATEWAY = "0.0.0.0"
MAX_ROUTES_PER_FILE = 1024
```

Run:

```bash
python3 ./asn_routes.py
```

The script creates one or more `.dat` files in the working directory.

## Output Format

Each generated line has this format:

```text
route add <NETWORK> mask <NETMASK> <GATEWAY> & rem AS<ASN>
```

Example:

```text
route add 2.60.0.0 mask 255.252.0.0 0.0.0.0 & rem AS12389
```

For an exact MOAS duplicate, multiple ASNs are listed in the comment:

```text
route add 1.2.0.0 mask 255.255.0.0 0.0.0.0 & rem AS100, AS200
```

The script does not execute the route commands. It only writes files.

## Output Splitting

By default, a single output file contains at most 1024 route commands:

```python
MAX_ROUTES_PER_FILE = 1024
```

If the generated route list is longer, additional files are created using a numeric suffix:

```text
ruroutes.dat
ruroutes(1).dat
ruroutes(2).dat
```

For example, 1761 routes produce:

```text
ruroutes.dat      # 1024 lines
ruroutes(1).dat   # 737 lines
```

## Configuration

Main options are defined in `asn_routes.py`:

```python
ASN_LIST = "3216,6697,6764,8901,12389,12876"
OUTPUT_FILE = "ruroutes.dat"
GATEWAY = "0.0.0.0"

RIPE_HOST = "riswhois.ripe.net"
RIPE_PORT = 43

CONNECT_TIMEOUT = 10
READ_POLL_TIMEOUT = 1
QUERY_TIMEOUT = 30
MAX_RETRIES = 3
RETRY_DELAY = 3
MAX_ROUTES_PER_FILE = 1024

DEBUG = False
ENABLE_IRRD_MULTICOMMAND = True
FETCH_ASN_NAMES = False
```

`ASN_LIST` accepts values with or without the `AS` prefix:

```python
ASN_LIST = "AS3216, 6697, 12389"
```

Duplicate ASN values are removed while preserving order.

## How It Works

Pipeline:

```text
ASN list
  -> RIPE RISwhois persistent TCP session
  -> IPv4 BGP prefixes by origin ASN
  -> IPv4 validation
  -> per-ASN deduplication
  -> per-ASN CIDR aggregation
  -> exact MOAS merge
  -> numeric IPv4 sorting
  -> Windows route command generation
  -> output validation
  -> atomic split-file write
```

Aggregation is intentionally done separately per ASN. If `AS100` has `1.0.0.0/24` and `AS200` has `1.0.1.0/24`, the script keeps them as two routes and does not collapse them into `1.0.0.0/23`.

## Progress and Failures

The script prints progress while connecting, fetching, aggregating, merging, sorting, validating, and writing files.

If at least one ASN fails due to a network, protocol, or data validation error, the run is considered unsuccessful and existing output files are not replaced.

Exit codes:

```text
0   success
1   general failure
2   configuration error
3   RIPE/network failure
4   output validation/write failure
130 interrupted by user
```

## Testing

Run syntax checks:

```bash
python3 -m py_compile asn_routes.py tests/*.py
```

Run unit tests:

```bash
python3 -m unittest discover -v
```

The tests cover ASN parsing, IRRd parser behavior, timeout polling, aggregation, MOAS merging, route sorting, output validation, and split-file writing.

## Live Test

A live run depends on RIPE RISwhois availability:

```bash
python3 ./asn_routes.py
```

To test without overwriting the configured output file:

```bash
python3 -c "import asn_routes; asn_routes.OUTPUT_FILE='/tmp/ruroutes_live.dat'; raise SystemExit(asn_routes.run())"
```

## Limitations

- IPv6 routes are not generated.
- ASN names are not included in generated `.dat` comments. Comments contain only ASN numbers.
- The script does not execute Windows route commands.
- The project does not provide a CLI argument parser yet; configuration is edited directly in `asn_routes.py`.
- Live results depend on current RIPE RIS visibility.

## License

MIT License. See `LICENSE`.
