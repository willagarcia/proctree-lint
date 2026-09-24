# proctree-lint

A linter for process tree snapshots. Point it at a text dump of `pid ppid
state command` rows and it reports structural problems by line number:
duplicate pids, processes whose parent doesn't exist in the snapshot, and
zombies.

I keep hitting the same problem when triaging a stuck box: someone pastes a
`ps -ef --forest` dump into a ticket, and figuring out which branch is
actually broken means reading it by eye. This tool turns that dump into a
file you can check with a script, in CI, or against a saved baseline.

## Input format

One process per line: `pid ppid state command`. `state` is the first letter
of the `ps` state (`R` running, `S` sleeping, `D` disk wait, `Z` zombie, `T`
stopped). Blank lines and lines starting with `#` are ignored, so you can
annotate a snapshot before checking it in.

You can build one directly from a live system:

```sh
ps -eo pid,ppid,state,comm --no-headers > snapshot.ptree
```

## Usage

```sh
cargo run --release -- examples/sample.ptree
```

Given `examples/sample.ptree`:

```
1 0 S init
100 1 S sshd
101 100 S sshd: worker
101 100 S sshd: worker
200 1 Z curl
300 999 S orphaned-daemon
```

it reports:

```
examples/sample.ptree:7: duplicate-pid: pid 101 already defined on line 6
examples/sample.ptree:8: zombie-process: pid 200 (curl) is a zombie; its parent never reaped it
examples/sample.ptree:9: orphan-process: pid 300 (orphaned-daemon) has ppid 999 which is not present in the snapshot
```

Exit code is 1 if any findings were reported, 0 otherwise, so it plugs into
a CI step without extra glue.

## Rules

| rule             | meaning                                                        |
|------------------|-----------------------------------------------------------------|
| `parse-error`    | a line doesn't have four fields, or pid/ppid isn't a number     |
| `duplicate-pid`  | the same pid appears more than once in the snapshot              |
| `orphan-process` | a process's ppid doesn't match any pid in the snapshot           |
| `zombie-process` | a process is in the `Z` state                                   |

## Status

Early. No dependencies, standard library only. See the issue tracker for
what's planned next (cycle detection, a `--baseline` mode to diff two
snapshots, depth limits).

## License

MIT, see [LICENSE](LICENSE).
