# Changelog

What each release changed for you, newest first. Each line is a commit's summary, linked to its full description and diff. Releases before 5.2.4 are described by their release commits.

## 5.3.2 - 2026-09-30

### Fixes

- Share one request per address among concurrent lookups and batches ([`ce16e52`](https://github.com/vpndetection-io/sdk-dotnet/commit/ce16e52214d5e273db534fcaae5fd2d8acda96b5))
- Reserve DownloadBytesAsync's array as the bytes arrive ([`5ca028a`](https://github.com/vpndetection-io/sdk-dotnet/commit/5ca028a06651cde190e5ad11ec2610999a92d91b))

## 5.3.1 - 2026-09-29

### Fixes

- Judge an IPv4-mapped address as the IPv4 address it carries ([`2256c07`](https://github.com/vpndetection-io/sdk-dotnet/commit/2256c0784011a55a6260cf0681716e0b00b2c638))
- Recognize 26 more reserved ranges as bogons, as the API does ([`9215a9d`](https://github.com/vpndetection-io/sdk-dotnet/commit/9215a9df4d6ff2a7a18bd1c1a0dbf487a46ef327))

## 5.3.0 - 2026-09-27

### Features

- Re-pin the spec to 2026.09.26, adding ClientIdMetadataDocumentSupported ([`bc36bc0`](https://github.com/vpndetection-io/sdk-dotnet/commit/bc36bc0aaf02487d1b7879374cad2a1e61b43af7))

## 5.2.4 - 2026-09-23

### Fixes

- End the poll's sleep at its deadline, and pin each required member ([`bedd356`](https://github.com/vpndetection-io/sdk-dotnet/commit/bedd35684902409ff407d9d7d00f41376a488552))
