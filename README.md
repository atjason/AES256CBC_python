# AES256CBC for python
Wrapper for AES 256 CBC using Python.

# Dependency

Depends on [cryptography](https://github.com/pyca/cryptography/)

```bash
$ pip install cryptography
```

Note: also refers to Swift version: [AES256CBC](https://github.com/atjason/AES256CBC)

# Usage

```python
txt = "Hello World."
password = AES256CBC.generate_password()

encrypted = AES256CBC.encrypt(txt, password)
decrypted = AES256CBC.decrypt(encrypted, password)

assert decrypted == txt
```

Note:

- The password must be exactly 32 chars long for AES-256.
- IV of AES is the first 16 chars of encrypted strings.
- The encrypted strings are base 64 encoded.
