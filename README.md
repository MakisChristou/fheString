# FheString
A Fully Homomorphic String library written in Rust using Zama's [tfhe-rs](https://github.com/zama-ai/tfhe-rs). 

## How it works
The binary given is not meant for production use but rather a proof of concept on how a FHE String library would work. The program takes as cli arguments the string, pattern, n, from and to and runs all supported algorithms and compares their results with the standard string library in Rust. It outputs the time it took as well as if the results match.


## Supported String functions
The supported string functions are the following:

- `contains` with clear / encrypted pattern
- `ends_with` with clear pattern / encrypted pattern
- `eq_ignore_case`
- `find` with clear pattern / encrypted pattern
- `is_empty`
- `len`
- `repeat` with clear / encrypted number of repetitions
- `replace` with clear pattern / encrypted pattern
- `replacen` with clear pattern / encrypted pattern
- `rfind` with clear pattern / encrypted pattern
- `rsplit` with clear pattern / encrypted pattern
- `rsplit_once` with clear pattern / encrypted pattern
- `rsplitn` with clear pattern / encrypted pattern
- `rsplit_terminator` with clear pattern / encrypted pattern
- `split` with clear pattern / encrypted pattern
- `split_ascii_whitespace`
- `split_inclusive` with clear pattern / encrypted pattern
- `split_terminator` with clear pattern / encrypted pattern
- `splitn` with clear pattern / encrypted pattern
- `starts_with` with clear pattern / encrypted pattern
- `strip_prefix` with clear pattern / encrypted pattern
- `strip_suffix` with clear pattern / encrypted pattern
- `to_lowercase`
- `to_uppercase`
- `trim`
- `trim_end`
- `trim_start`
- `+` (concatenation)
- Comparisons between strings `>=`, `<=`, `!=`, `==`


## Buidling 

```bash
cargo b --release
```

## Example input 
```bash
$ fhestring --string "hello" --pattern "ello" --n 1 --from "ello" --to "_llo"
```

## Cli Arguments
```bash
$ fhestring --help
    Finished release [optimized] target(s) in 0.08s
     Running `target/release/fhestring --help`
A FHE string implementation using tfhe-rs

Usage: fhestring --string <STRING> --pattern <PATTERN> --n <N> --from <FROM> --to <TO>

Options:
  -s, --string <STRING>    The string to do the processing on
  -p, --pattern <PATTERN>  The pattern for the algoritmhs that need it
  -n, --n <N>              The number of times to make an operation for the algoritmhs that need it
  -f, --from <FROM>        What will be replaced (for replace algorithms)
  -t, --to <TO>            What will replace it (for replace algorithms)
  -h, --help               Print help
  -V, --version            Print version
```


