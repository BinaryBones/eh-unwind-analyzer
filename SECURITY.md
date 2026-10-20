# Security

## Safe Use

Static analysis reads a PE file as data and does not execute it. Dynamic mode
does execute the target under the Windows Debug API.

For unknown or hostile files:

- use a disposable Windows VM with snapshots;
- disable shared folders, clipboard, credentials and unnecessary networking;
- run without administrator privileges;
- do not analyze on a production workstation;
- preserve the input SHA-256 and generated reports outside the VM.

The debugger is an evidence collector, not a malware sandbox. It does not
contain filesystem, registry, process, network or kernel activity.

## Report Handling

Reports can contain file paths, section names, addresses and runtime module
names. Arguments passed to the target after `--` are redacted from report
metadata, but the report may still be sensitive.

The HTML report is self-contained and uses no external assets. Input-derived
text is escaped before serialization.

## Reporting A Vulnerability

Do not publish a proof-of-concept containing a real malicious sample or
sensitive report. Provide:

- affected version and platform;
- minimal synthetic reproducer where possible;
- command line and exit code;
- sanitizer output or crash trace;
- expected and observed behavior.

Until a project-specific private security contact is configured, report the
issue privately to the repository owner.
