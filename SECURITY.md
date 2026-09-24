# Security policy

## Reporting a vulnerability

Report it privately, by email to **evand.ukss@gmail.com**. Do not open a public issue, pull request or
discussion about it.

A report the maintainer can act on says:

- the commit you built from;
- the host's kernel release and architecture (`uname -r -m`);
- the configuration you ran, with anything private removed;
- what the observer did, what you expected it to do, and the steps that reproduce it.

## Supported versions

No release has been published. Fixes are made on `main`, and the latest commit on `main` is the only
supported version.

## What counts as a vulnerability

The observer reads the plaintext of other processes, so its limits are the security boundary. A way to
make it do any of the following is a vulnerability:

- observe a process that no target in its configuration selects, or one that `exclude` names;
- read the memory of a process no target approves, or read an approved process's memory beyond the
  buffers and byte counts handed to the TLS library calls it attaches to;
- write to any process's memory;
- keep the capabilities it attached with once its probes are placed;
- listen on a network socket, or send anything off the host;
- create its log, pid file, spool or account so that a user other than the one running it can read them
  (it creates files `0600` and directories `0700`);
- act on a configuration section it does not implement instead of refusing the configuration.

## What does not count

- **The spool holds the captured plaintext.** Every request and response an approved process sent or
  received is in the session's spool files, base64-encoded, until you delete them. That is what the
  observer is for. Whoever can read those files - the user that ran the observer, and root - can read
  that traffic, credentials and personal data included.
- **Running it needs root, or the capabilities listed in
  [docs/compatibility.md](docs/compatibility.md).** A report that assumes the attacker already holds
  them is not about the observer.
