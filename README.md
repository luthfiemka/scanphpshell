## Scan PHP Shell

A simple script to scan shell script on your system. The results can be use for further investigation.

### How to Use

```python3 scanphpshell.py /home```

where the `/home` is the target directory.

### Output format

the default output format is:

```{file_path} {permissions} {owner} {md5_hash} Line:{line_number} FOUND:{term}```

example:

```/home/user/public_html/index.php 0o755 user:user 65172ab56bced1112128 Line:1 FOUND:eval(```
