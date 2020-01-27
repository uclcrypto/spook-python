# Spook Python Implementation

Implementation of the spook cipher in Python, intended for analysis purposes.

**CAUTION** This implementation is NOT FITTED for use with real-life data: it
is sensitive to timing side-channel attacks and is extremely inefficient.

## Usage

The `spook_encrypt` and `spook_decrypt` functions take as input bytes objects. The variant is selected according to the global constant `SMALL_PERM` and to the length of the input `k` (16 bytes for `su` and 32 bytes for `mu`).

## License

This software distributed under the terms of the MIT license. See [LICENSE](LICENSE) for details.

## Changelog (see git log for details)

- `v1.0` Initial version
- `v2.0` Remove the `p` parameter from the API to match the NIST API.

