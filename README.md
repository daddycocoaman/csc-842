# CSC-842
Tools written for CSC-842 at Dakota State University

---

## Cycle 1 - CookieSnake
Python script to output Firefox, Chrome 80+, and Edge (Chromium-based) cookies.

### Requirements
- Windows only
- Python 3

### Dependencies
- pycryptodome
- pywin32 

### Installation

`pip install requirements.txt`

### Usage
```
CookieSnake.py [-h] [-f] [-c] [-e] [-d]

optional arguments:
  -h, --help  show this help message and exit
  -f          Grab Firefox cookies
  -c          Grab Chrome (v80+) cookies
  -e          Grab Edge (v80+) cookies
  -d          Filter cookies by domain. [Usage: -d google.com,microsoft.com]
  ```

  ---