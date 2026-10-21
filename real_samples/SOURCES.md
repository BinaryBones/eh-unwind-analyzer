# Optional real-world PE corpus

Third-party executables are local inputs for compatibility tests. They are
not included in this repository or in source/release archives. Download only
from official sources and follow each project's redistribution terms.

## Historical source inventory

The following inventory records archives used for a June 2026 local run.
It does not assert results for the current analyzer. Upstream downloads can
change; these hashes identify the archived inputs, not future downloads.

| Source | Download | SHA-256 |
|---|---|---|
| Microsoft Sysinternals Suite | `https://download.sysinternals.com/files/SysinternalsSuite.zip` | `e45ce0b3fd6d0457e253f132ef086c6c4715def16e59433de2cb5dfe2c16a76f` |
| CPython 3.14.4 embeddable AMD64 | `https://www.python.org/ftp/python/3.14.4/python-3.14.4-embed-amd64.zip` | `cda80a9b1e75c0f1b4f9872ca1b417f0d19bce32facc811aea9180e70fad5fb9` |
| ripgrep 15.1.0 Windows MSVC x64 | `https://github.com/BurntSushi/ripgrep/releases/download/15.1.0/ripgrep-15.1.0-x86_64-pc-windows-msvc.zip` | `124510b94b6baa3380d051fdf4650eaa80a302c876d611e9dba0b2e18d87493a` |
| jq 1.8.1 Windows AMD64 | `https://github.com/jqlang/jq/releases/download/jq-1.8.1/jq-windows-amd64.exe` | `23cb60a1354eed6bcc8d9b9735e8c7b388cd1fdcb75726b93bc299ef22dd9334` |
| 7-Zip 26.01 x64 installer | `https://www.7-zip.org/a/7z2601-x64.exe` | `d64a0468f5b5b0b0fc5b2188450bcd655b70809d97b1c4535f2884635094377d` |

## Run a current check

Place the selected PE32+ AMD64 files in `real_samples/inbox/`, then run:

```sh
python tests/run_real_corpus.py build/release/eh_unwind_analyzer real_samples/inbox real_samples/reports
```

On Windows, append `.exe` to the analyzer path. This runner performs static
analysis without executing the input files and validates report schemas and
semantic invariants. Inspect the new summary for the build being tested.
Downloaded files and generated reports are excluded from Git.
