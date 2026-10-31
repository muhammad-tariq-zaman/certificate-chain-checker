# certificate-chain-checker

Verify a PEM certificate chain with the standard library: flag expired certificates and broken issuer/subject links between consecutive certificates.

## How to run

```sh
python3 main.py chain.pem
```

## Example output

```
certificate 1: OK (expires 2027-01-01)
certificate 2: OK (expires 2028-01-01)
Chain verdict: OK (2 certificate(s)).
```

Standard library only. Run the tests with `python3 -m unittest discover`.
