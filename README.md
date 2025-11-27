<h3 align="center"><code>dnspeek</code> · Fast DNS recon in Go</h3>
<p align="center">
	<a href="#features">Features</a> •
	<a href="#getting-started">Getting Started</a> •
	<a href="#usage">Usage</a> •
	<a href="#benchmarks">Benchmarks</a> •
	<a href="#credits">Credits</a> •
	<a href="#license">License</a>
</p>

---

[dnspeek] is a Go DNS reconnaissance CLI
built for clear output and sensible defaults. It handles general enumeration,
brute force, reverse sweeps, SRV/TLD probes, AXFR attempts, and DNSSEC walks
while keeping results easy to review.

## Features

- Equivalent [dnsrecon] feature set and **~72x faster**. See
  [Benchmarks](#benchmarks).
- General enum (SOA, NS, MX, A/AAAA, TXT/SPF, CAA, SRV) with optional AXFR, SPF
  expansion, crt.sh names, and DNSSEC NSEC walk.
- Brute force hosts from lists, with wildcard-aware filtering.
- Reverse sweeps over CIDRs or start-end ranges.
- Cache snooping.
- SRV and TLD probes with thread control.

## Getting Started

> [!IMPORTANT]
> Pentesting tools must only be used in lab environments or on systems you are
> explicitly authorized to test. Running this tool against systems you do not
> own can be illegal and unethical.

### Installing

Install quickly via Homebrew:

```sh
brew install Neved4/tap/dnsrecon
```

### Building

Clone and build from source:

```sh
git clone https://github.com/Neved4/dnspeek
cd dnspeek
go mod download
go build -o dnspeek ./cmd/dnspeek
```

## Usage

Command flags and key options:

```sh
usage: dnspeek -d <name> [-acfikpqsz] [-r <cidr|start-end>] [-t <type>]
  [-n <servers>] [-D <file>] [-T <num>] [-w <seconds>] [-C]

Options:
  -d, -domain    Target domain (required for most scans)
  -r, -range     CIDR or start-end for reverse lookups
  -t, -type      Scan types: std, brt, srv, tld, rvl, axfr, cache, zonewalk
  -n, -ns        Comma list of resolvers
  -D, -dict      Wordlist for brute force
  -T, -threads   Concurrency level
  -p, -tcp       Force TCP
  -f, -wildcard  Drop wildcard IPs during brute force
  -i, -ignore    Continue brute force when wildcard DNS is present
  -s, -spf       Reverse SPF ranges during std
  -z, -zone      Attempt DNSSEC NSEC walk during std
  -q, -caa       Include CAA lookups during std
  -c, -cache     Run cache snooping
  -k, -crt       Scrape crt.sh during std
  -a, -axfr      Try zone transfer in std
  -w, -timeout   Per-query seconds
  -C, -no-color  Disable ANSI output
```

Defaults: type `std`, dict `namelist.txt`, threads `20`, timeout `5`
seconds.

### Configuration

Wordlists live in `data/`. Set `DNSPEEK_DATA` to use a custom directory.

### Examples

Example invocations for standard, brute, and reverse runs:

- **Standard enum with AXFR try:**

  ```sh
  dnspeek -d 'google.com' -t 'std' -a
  ```

- **Brute force with custom list:**

  ```sh
  dnspeek -d 'google.com' -t 'brt' \
  	-D 'subdomains-top1mil-5000.txt'
  ```

- **Reverse sweep over CIDR:**

  ```sh
  dnspeek -r '192.0.2.0/29' -t 'rvl' -d 'google.com'
  ```

- **All scan types enabled:**

  ```sh
  dnspeek -d 'google.com' -r '192.0.2.0/29' -acfikpqsz \
  	-t 'std,brt,srv,tld,rvl,cache,zonewalk' \
  	-D 'data/namelist.txt' -n '1.1.1.1,8.8.8.8' -T '64' -w '5'
  ```

## Benchmarks

[dnspeek] is ~72x faster than [dnsrecon] on `google.com` standard scans
(timeout 2s, threads 5).

Results:

| Command    |     Mean [ms] | Min [ms] | Max [ms] |     Relative |
| :--------- | ------------: | -------: | -------: | -----------: |
| `dnspeek`  |    24.2 ± 1.0 |     23.0 |     25.3 |         1.00 |
| `dnsrecon` | 1741.5 ± 98.0 |   1606.0 |   1838.4 | 72.06 ± 5.04 |

Command:

```sh
hyperfine 'dnspeek -d google.com -t std -w 2 -T 5 -C' \
	'dnsrecon -d google.com -t std --lifetime 2 --threads 5'
```

## Credits

Shout out to [dnsrecon], the OG inspo.

## License

This repository is licensed under the terms of the [MIT License](LICENSE).

See the [LICENSE](LICENSE) file for details.

[dnspeek]: https://github.com/Neved4/dnspeek
[dnsrecon]: https://github.com/darkoperator/dnsrecon
