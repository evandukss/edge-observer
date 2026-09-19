# The observer, from download to inspected results

The observer shows what crossed the TLS boundary of processes you approve - the HTTP/1.1 requests and
responses they send and receive - without a proxy, a certificate, or any change to those processes. It
runs on Linux, reads processes that use OpenSSL 3.x as a shared library, and writes what it saw to
files on the same host. Nothing leaves the host. There is no registration, no account and no hosted
service.

This document is the whole path, in four steps: download and verify, configure, run, inspect. Everything
it needs is in this file or in the archive beside it.

## What is in the archive

The archive is `observer-linux-amd64.tar.gz`. It unpacks into one directory, `observer-linux-amd64`,
holding exactly these files:

    observer               the program: one static file, linux/amd64, needing nothing installed
    README.md              this document
    observer.config.json   the simplest configuration the program runs, for you to edit
    HOST-REQUIREMENTS.md   what a host must provide, each item judged by `observer preflight`
    LICENSE                Mozilla Public License 2.0
    COMMIT                 the commit of the repository the archive was built from, one line

Beside the archive, and not inside it, is `observer-linux-amd64.sha256`: the digest of the program file.

There is no version number. What you download is the archive a build produced from one commit, named
in `COMMIT`, and it is not a release.

## 1. Download and verify

No archive is published yet.

## 2. Configure

    cd observer-linux-amd64

The observer reads one JSON file. Edit `observer.config.json`; four things in it are yours to set.

**Where it writes.** `observer.directory` is where the observer keeps its pid file and one directory
per run under `sessions`; it is created if missing. `observer.log` is `stdout`, or an absolute path for
a log file.

**What it observes.** `observation_scope.targets` is the list of processes you approve, and the
observer attaches to nothing else. For one process already running, find what identifies it:

    pgrep -a <program name>                 # its pid and command line (or find it with ps)
    readlink /proc/<pid>/exe                # the file the kernel runs: this is "exe"
    tr '\0' '\n' < /proc/<pid>/cmdline      # its command line, one entry per line

Then write the target, with `args` being every command-line entry after the first:

    {
      "name": "api",
      "match": {"exe": "/usr/bin/python3.11", "args": ["/srv/api/server.py"]},
      "descendants": {"existing": true, "future": true, "boundary": "exec_ends_the_grant",
                      "root_exit": "survivors_keep_their_grants", "replacement": "needs_restart"}
    }

Every condition in `match` must hold. Besides `exe` and `args` there are three more: `cgroup`, a
path on the unified cgroup hierarchy that the process must be in or below; `port`, a listening TCP port
whose holders are selected, with an optional `interface`; and `pid`, which names one process as
`{"pid": N, "start": S, "boot": B}`. `descendants.existing` and `descendants.future` choose whether the
matched process's children already running, and the ones it creates later, are observed too; the other
three answers are fixed and must be written exactly as above. `observation_scope.exclude` lists matches
that are never observed, whatever a target says.

**Leave every other section as it is in the file.** The program implements what that file asks for -
every connection of an approved process, kept on this host - and refuses any other value there with a
message naming the section, rather than ignoring it.

Check what it would select, attaching nothing:

    ./observer dry-run observer.config.json --text

A target that selected nothing says why. Fix the target until yours shows the process you meant.

## 3. Run

Attaching needs root, or the capabilities `HOST-REQUIREMENTS.md` lists. Ask first whether this host
can run it, as the user that will run it:

    sudo ./observer preflight observer.config.json --text

It answers `READY`, or `NOT READY` naming each requirement missing, or `INDETERMINATE` naming what it
could not read, and exits 0 only on `READY`. It attaches nothing. Do not start on anything but `READY`.

    sudo ./observer start observer.config.json

It runs in the foreground and prints one JSON record per line; the first says it activated and what it
attached to. Now use the service you approved so traffic crosses it - nothing is observed on a quiet
process. From another terminal, `sudo ./observer inspect observer.config.json --text` shows the running
session's account as it stands.

    sudo ./observer stop observer.config.json

(or Ctrl-C in the first terminal) ends the run. `stop` prints the session it ended, whether it sealed
completely, and the path of the account it sealed.

## 4. Inspect

A finished run is a directory: `<observer.directory>/sessions/<session>`, the session `stop` named.

    sudo ./observer inspect /var/lib/observer/sessions/<session> --text

That reads the directory alone. No running observer and no configuration is needed, so the directory
can be copied to another machine and inspected there with the same program. Its files are readable only
by the user that ran the observer - root, above - so either inspect as that user or copy the directory
and give the copy to yourself. Without `--text` it prints the account as JSON.

The account says what was attached, what was seen, and what was lost. **Read what it says was lost
before believing anything else in it**: a run that lost events is not evidence about what crossed the
host. And a run that saw nothing is only evidence of a quiet process if the account also says the
probes were attached.

After the account, `--text` prints the exchanges reconstructed from the spool beside it: each connection
under its process, with whether that process was the server or the client, and under it each request's
method and path and the status of the response to it, every header by name, and each body by its size
and JSON shape. It prints no header value and no body byte. Reconstruction runs here, as the directory
is read, on the machine running `inspect`, and it reads the session's whole spool, every value
included, into memory to find that structure. Leaving the values out of what it prints removes nothing:
they were read to build the view, and the spool still holds them. A directory holding the account alone
says that nothing was reconstructed, rather than showing a session in which nothing crossed.

The header values and body bytes are in the spool files beside the account, in full: `.jsonl` files of
one JSON record per line, where each record of what crossed carries those bytes base64-encoded. That is
plaintext in all but spelling - whatever credentials and personal data the observed traffic carried are
in it, one decode away - and it stays on this host until you delete it.
