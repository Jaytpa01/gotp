# 🔒 gotp

[![GitHub Release](https://img.shields.io/github/v/release/Jaytpa01/gotp)](https://github.com/Jaytpa01/gotp/releases/latest)
[![Go Reference](https://pkg.go.dev/badge/github.com/Jaytpa01/gotp.svg)](https://pkg.go.dev/github.com/Jaytpa01/gotp)
[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](https://choosealicense.com/licenses/mit/)
[![Go Report Card](https://goreportcard.com/badge/github.com/Jaytpa01/gotp)](https://goreportcard.com/report/github.com/Jaytpa01/gotp)

gotp is a library for generating and verifying One-Time Passwords (OTP).

It supports both the TOTP (Time-based One-Time Password) algorithm as defined in [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238), and the HOTP (HMAC-Based One-Time Password) algorithm as defined in [RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226).

Each package has been tested against the test vectors provided in their respective RFC specifications.

## Installation

```bash
go get -u github.com/Jaytpa01/gotp
```

## Features

- **TOTP:**
  - Generate OTPs based off of the current time, or a specified time.
- **HOTP:**
  - Generate OTPs based off of a counter value.
- **High-Level OTP Handling:**
  - Unified interface for both TOTP and HOTP generation.
  - Easy to use API with flexible configuration and sensible defaults.

## Usage

`TODO`: provide usage examples for the high-level otp handling, as well as examples for direct use of the hotp and totp packages.

## Options

`TODO`: provide a reference for all options when creating a new otp instance. (functional options pattern)
