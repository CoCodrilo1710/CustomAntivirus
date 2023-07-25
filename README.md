# Custom Antivirus

This script is compatible only with Linux ( for now ), because it analyzes the string found in a given file with "strings" command available in Linux.
It have 2 type of analyzing: by the hash or by malicious strings found in the file.

For testing you have 3 examples:

- "test_nemal" - non-malicious
- "test1_mal" - malicious by hash
- "test2_cuv_mal" - malicious by strings

## Instructions

``` ./antivirus file_path ```
