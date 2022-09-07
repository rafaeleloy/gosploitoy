# gosploitoy

A simple golang tool to search for exploit-db cve's

## Example usages

Single URL:

```
echo CVE-2021-44228 | gosploitoy
```

Multiple URLs:

```
cat cves.txt | gosploitoy -t 10 -r
```

## Installation

First, you'll need to [install go](https://golang.org/doc/install).

Then run this command to download + compile gosploitoy:
```
go install github.com/rafaeleloy/gosploitoy@latest
```

## Command-line options
```
Usage of gosploitoy:
  -r    Retry on errors.
  -t int
        Number of workers to utilise. (default 5)
```