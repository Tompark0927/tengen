# NOTICE

## Why PolyForm Noncommercial 1.0.0

Tengen is pre-audit research code. The chosen license
([PolyForm Noncommercial 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0/))
explicitly forbids commercial use by third parties while permitting:

- personal study, experimentation, and hobby projects
- academic and public-research use
- use by charitable, educational, or governmental organizations

This matches our current maturity: we do not want anyone — including the
authors — running the code with real users or production data until an
external cryptographic audit completes. The license enforces that
constraint beyond documentation.

### Upgrade path

Once the codebase has been reviewed by an independent auditor
(see `AUDIT_RFP.md`) and cleared for production use, the copyright holder
may relicense the repository under a more permissive license (e.g., MIT,
Apache 2.0, or BSL). The PolyForm Noncommercial license is designed for
this transition: the copyright holder retains every right to issue
additional licenses, including commercial ones, in parallel.

## Third-party components

Tengen depends on the following libraries. Their licenses apply to the
respective code and remain independent of the license above.

| Dependency       | Version | License | Purpose                                 |
|------------------|---------|---------|-----------------------------------------|
| `@noble/curves`  | ^1.4.0  | MIT     | Ed25519 + X25519 curve arithmetic       |
| `@noble/hashes`  | ^1.4.0  | MIT     | SHA-512 used by FROST                   |
| `zod`            | ^3.23.8 | MIT     | Schema-gated input validation in Ward   |
| `tsx` (dev only) | ^4.16.0 | MIT     | TypeScript execution for CLI + scripts  |
| `typescript`     | 5.5.3   | Apache-2.0 | Type-checker                        |
| `@types/node`    | ^20.14.0 | MIT    | Node stdlib type definitions            |

The Go loader under `loader/` uses only the Go standard library.

## Required attribution

Distributions of Tengen or derived works must retain a copy of the
`LICENSE` file and the following notice:

> Required Notice: Copyright 2026 Tengen contributors
> (https://github.com/tengen-dev/tengen)

## Warranty and liability

**There is none.** See the `No Liability` section of the license. The
authors, contributors, and any AI co-author involved in producing this
code do not and cannot indemnify you against losses, regulatory
enforcement, or any other adverse outcome from using this software.
