# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.0.x   | ✅ Yes    |

## Reporting a vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Email: sachinruhil11@gmail.com

Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact

You will receive a response within 72 hours.
We will credit researchers in the release notes.

## Cryptographic foundation

@pq-jwt/hybrid uses @noble/curves (ECDSA P-256), @noble/post-quantum (ML-DSA, SLH-DSA),
and @noble/hashes. We do not implement our own cryptographic primitives.
