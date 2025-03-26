# Vevde security utils
A reusable library of security functions and tools. This package is not tied to any web framwork. So multiple 
Python web frameworks like Django, Fast API, Flask can use it.

# 1. Install
pip install vevde-security-utils

# 2. Example usage
See `tests` package for each function  

| # | Feature                              | Details / Files                               |  
|---|--------------------------------------|-----------------------------------------------|  
| 1 | Symmetric algorithms                 | `AES-256`, `Camellia-256`                     |
| 2 | Create Encrypted HMAC / Decrypt HMAC | `vevde_security_utils/crypt/hmac.py`          |
| 3 | Hash, Signatures                     | `vevde_security_utils/crypt/signatures.py`    |
| 4 | File encryption                      | `vevde_security_utils/crypt/file_ops.py`      |

#### Notes
>> File encryption and decryption:  
> a) Read chunk size (eg. 1024, 2048...) and cipher block size (16 for AES and Camellia) must be provided by client applications
 

# 3. License
Apache2 License
