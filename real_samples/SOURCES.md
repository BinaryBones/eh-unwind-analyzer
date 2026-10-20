# Real-World PE Corpus

Downloaded on 2026-06-07 from official project sources. These files are used
only for local static compatibility testing and must not be redistributed in a
source or release archive.

| Source | Download | SHA-256 |
|---|---|---|
| Microsoft Sysinternals Suite | `https://download.sysinternals.com/files/SysinternalsSuite.zip` | `e45ce0b3fd6d0457e253f132ef086c6c4715def16e59433de2cb5dfe2c16a76f` |
| CPython 3.14.4 embeddable AMD64 | `https://www.python.org/ftp/python/3.14.4/python-3.14.4-embed-amd64.zip` | `cda80a9b1e75c0f1b4f9872ca1b417f0d19bce32facc811aea9180e70fad5fb9` |
| ripgrep 15.1.0 Windows MSVC x64 | `https://github.com/BurntSushi/ripgrep/releases/download/15.1.0/ripgrep-15.1.0-x86_64-pc-windows-msvc.zip` | `124510b94b6baa3380d051fdf4650eaa80a302c876d611e9dba0b2e18d87493a` |
| jq 1.8.1 Windows AMD64 | `https://github.com/jqlang/jq/releases/download/jq-1.8.1/jq-windows-amd64.exe` | `23cb60a1354eed6bcc8d9b9735e8c7b388cd1fdcb75726b93bc299ef22dd9334` |
| 7-Zip 26.01 x64 installer | `https://www.7-zip.org/a/7z2601-x64.exe` | `d64a0468f5b5b0b0fc5b2188450bcd655b70809d97b1c4535f2884635094377d` |

The selected inbox contains only files identified by the host `file` utility
as PE32+ x86-64. No downloaded executable is launched on macOS.

## Validation Result

- Selected files: 106 (140.4 MiB).
- Runtime functions parsed: 174,795.
- Valid schema and semantic reports: 106/106.
- Crashes, timeouts and invalid reports: 0.
- UNWIND parse failures and structural anomalies: 0.
- Non-zero heuristic scores on this benign corpus: 0.

Generated reports are intentionally not stored in the release workspace
because they add roughly 95 MiB and are fully reproducible:

```sh
python3 tests/run_real_corpus.py \
  build/release/eh_unwind_analyzer real_samples/inbox /tmp/ehua-real-reports
```

The June Windows evidence, including its machine-readable summary, is retained
separately in `reports/dynamic_validation_2026-06-08/`.
