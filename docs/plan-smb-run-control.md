# Plan: run control for permissionreset-smb (state dir, stop, resume, status)

Status: **sections 2 to 7 are built for `check` (not `apply`), qualification (section 8) pending.**
Written against `main` at `2980615`.
Depends on: nothing. It can land before or after [plan-smb-dotnet10.md](plan-smb-dotnet10.md).
Needed by: the Run monitor of the Windows GUI ([plan-smb-gui.md](plan-smb-gui.md), section 8).

## 1. Why

The GUI must show progress, pause a run, resume it and show results, also after the GUI itself is
closed and opened again. The CLI cannot support that today:

- `check` streams one JSON record per object on stdout and prints a summary on stderr at the end.
  It writes no files, so a run that stops leaves nothing to resume from.
- There is no way to ask a running `check` to stop cleanly. Killing the process loses the summary.
- There is no progress information during the run, only per-object records.

`DESIGN-write-path.md`, section 3.4, already requires directory-level checkpoint and resume for
the write path (phase 2). This plan builds that mechanism for `check` first, where a mistake costs
nothing, so that phase 2 inherits a tested mechanism.

The GUI is one client of this. An operator in a shell gets the same features.

## 2. Design rules

- The CLI owns run state. The GUI reads files the CLI writes and creates one stop file. It never
  edits the CLI's state.
- Files, not pipes. A pipe dies with the GUI; files let the GUI reattach to a run it started
  earlier, and let an operator inspect a run from a shell.
- Every file the CLI rewrites is written to a temp name in the same directory and renamed into place
  (`File.Move(..., overwrite: true)`), so a reader never sees half a file.
- Without `--state-dir`, behavior and output are exactly as today. Existing tests must pass
  unchanged.
- The stdout record format does not change. New information goes into new files.

## 3. New options

| Option | Commands | Meaning |
|---|---|---|
| `--state-dir DIR` | `check` (later `apply`) | Write run state to DIR. DIR must not exist, or must be empty, unless `--resume` |
| `--resume` | `check` (later `apply`) | Continue the run in `--state-dir`. Refused if the plan, root or command differ from the manifest |
| `--status-interval SECONDS` | `check` (later `apply`) | How often `status.json` is rewritten. Default 1. Needs `--state-dir` |

Option order follows the current parser: options before `PLAN.json ROOT`.

## 4. State directory layout

```text
DIR/
  run.json          manifest, written once at start, rewritten at each end of a run segment
  records.jsonl     one line per object, the same JSON as stdout, appended
  checkpoint.jsonl  completed subtrees, appended
  status.json       current progress, rewritten every --status-interval
  STOP              created by the operator or the GUI to ask for a clean stop; the CLI deletes it
  segments/         one stderr log per run segment: 001.log, 002.log, ...
```

### 4.1 `run.json`

```json
{
  "schema": 1,
  "run_id": "2026-11-27T10-51-04Z-8412",
  "command": "check",
  "tool_version": "0.2.0",
  "runtime": ".NET 10.0.x",
  "plan_path": "C:\\runs\\eng\\plan.json",
  "plan_sha256": "9f3c...a1e2",
  "root": "\\\\array01.example.com\\eng\\dept",
  "workers": 16,
  "identity": "EXAMPLE\\alice",
  "elevated": true,
  "privileges": ["SeBackupPrivilege"],
  "segments": [
    { "n": 1, "started": "2026-11-27T10:51:04Z", "ended": "2026-11-27T10:55:12Z", "end": "stopped", "exit": 3 },
    { "n": 2, "started": "2026-11-27T11:02:40Z", "ended": null, "end": null, "exit": null }
  ],
  "state": "running"
}
```

- `state` is one of `running`, `stopping`, `stopped`, `completed`, `failed`.
- A run segment is one process. A run that is stopped and resumed twice has 3 segments.
- `identity` is the process's user name as Windows reports it. With a network-only logon
  ([plan-smb-gui.md](plan-smb-gui.md), section 6) also record the network identity in
  `network_identity`.
- `--resume` compares `command`, `plan_sha256` and `root`. A difference is refused with exit 2 and
  a message that names the field. The plan file can move; its hash cannot change.

### 4.2 `status.json`

```json
{
  "run_id": "2026-11-27T10-51-04Z-8412",
  "segment": 2,
  "state": "running",
  "updated": "2026-11-27T11:04:12Z",
  "objects": 1284550,
  "outcomes": { "ok": 1201377, "write": 412, "follows": 80915, "keep": 1630, "excluded": 204, "reparse": 3, "error": 9 },
  "forms": { "inherits": 1270011, "explicit_plus_inherits": 12902, "protected": 1637 },
  "not_processed": 0,
  "dirs_queued": 3120,
  "dirs_done": 88421,
  "rate_per_sec": 4920,
  "current": ["dept/projects/2026/q3", "dept/projects/2026/q4"],
  "previous_total": 2071388
}
```

- Counts include every segment of the run, not only the current one.
- `current` lists up to 8 directories that workers are in now. It is for display only.
- `previous_total` is the object count of the last completed run with the same `root` and
  `plan_sha256` in the same parent directory of state dirs, if one exists; else it is absent. The
  CLI never estimates a total by itself. The GUI shows a percentage and a time left only when this
  field is present, and labels it "from the previous run".

### 4.3 `records.jsonl`

The same line the CLI prints on stdout, one per object. With `--state-dir`, stdout still gets the
records, so shell pipelines keep working.

After a resume, an object in an incomplete directory is checked again and gets a second line. A
reader must take the **last** line for a path. `check` writes nothing, so a repeat is harmless;
for `apply`, the compare finds the object right and writes nothing (`DESIGN-write-path.md`,
section 3.4).

### 4.4 `checkpoint.jsonl`

One line per **completed subtree**: `{"dir":"dept/projects/2026/q3"}`. A subtree is complete when
the directory, all its files and all its subdirectory subtrees are complete.

To find that, each directory node keeps a pending count: 1 for its own listing, plus 1 for each
subdirectory queued. A subdirectory that completes decrements its parent's count. A count that
reaches 0 marks the directory complete and decrements its parent. This keeps the order of the
current walk (a directory is checked before its children are queued) and needs no global lock
beyond the existing emit lock.

To keep the file small, write a line only for a subtree whose parent is not yet complete; when a
parent completes, its line covers its children. On load, the CLI keeps the outermost entries.
`docs/CHECKPOINT_SCALE.md` describes the growth of the NFS tool's checkpoint; use it to size this
file on a large tree, and record the measured size for a 2-million-object tree in the PR.

Flush `checkpoint.jsonl` at least once per `--status-interval`, and at each clean stop.

## 5. Stop and resume

### 5.1 Stop

A clean stop is asked for in one of 3 ways:

1. The file `DIR/STOP` appears. The CLI checks for it once per status interval.
2. Ctrl+C or Ctrl+Break in the console (`Console.CancelKeyPress`; set `e.Cancel = true`).
3. The console window is closed (`CTRL_CLOSE_EVENT`). Windows gives about 5 seconds, so do the same
   steps with a short deadline.

On a stop request:

1. Set `state` to `stopping` in `status.json` and `run.json`.
2. Workers take no new directory from the queue.
3. A worker finishes the object it is on. For phase 2 `apply`, a write and its read-back (guard G2,
   `DESIGN-write-path.md`, section 5.2) are one unit and are never split by a stop.
4. Flush `records.jsonl` and `checkpoint.jsonl`.
5. Write the final `status.json`, close the segment in `run.json` with `end: "stopped"`.
6. Delete `STOP`.
7. Exit with code **3**: stopped on request, resumable.

Without `--state-dir`, a Ctrl+C stops the same way but there is nothing to resume, and the exit
code is 3 with the message `check: stopped; nothing to resume (no --state-dir)`.

Pause in the GUI is a stop. Resume in the GUI is a new process with `--resume`.

### 5.2 Resume

1. Read `run.json`; refuse on a mismatch (4.1). Refuse if `state` is `running` and the process in
   the last segment is still alive (compare a PID and the process start time, both recorded in the
   segment). This stops 2 processes from sharing one state dir.
2. Load `checkpoint.jsonl` into a set of completed subtrees.
3. Load the outcome counts from the last `status.json`, so totals continue.
4. Walk from the root as usual. A directory in the completed set is pruned: not listed, no records,
   counted in `status.json` as already done. A directory that is not complete is visited again.
   Its own descriptor is read again, because its node (the desired DACL its children inherit) is
   not stored. This repeats at most the reads on the path from the root to each incomplete
   directory.
5. Append a new segment to `run.json`.

### 5.3 Exit codes

| Code | Meaning | Change |
|---|---|---|
| 0 | every object checked (and with `--validate`, every one ok) | none |
| 1 | an object or directory failed, a privilege is missing, or `--validate` found a difference | none |
| 2 | usage error, including a refused `--resume` | none |
| 3 | stopped on request; resumable when `--state-dir` was given | **new** |

## 6. Code layout

- `PermissionReset.Smb.Core`: a `RunState` type (manifest, checkpoint set, counts) and a
  `CancellationToken` parameter on `Checker.Run`. The pending-count tracking goes into `Checker`.
  Keep Core free of Win32 calls, so all of this tests on Linux.
- `PermissionReset.Smb` (CLI): option parsing, the files, the console handlers, the STOP poll.
- The stdout serializer (`Cli.Json`) is shared by stdout and `records.jsonl`, so the two never
  differ.

## 7. Tests (offline, fake `ITree`)

1. Without `--state-dir`, every existing CLI test passes unchanged.
2. **Stop-and-resume equals one run.** For a fake tree of a few thousand objects, stop after N
   objects for several N (including 0, 1 and the last object), resume, and compare the last record
   per path with a single uninterrupted run. They must be equal, and the final counts must be equal.
3. **Stop twice.** Same as 2, with 2 stops.
4. **Refusals.** `--resume` with a changed plan hash, a changed root, a changed command, and with a
   live process in the last segment. Each exits 2 and names the reason.
5. **Atomic files.** A reader that loads `status.json` in a tight loop during a run never gets a
   parse error.
6. **Checkpoint compaction.** After a completed run, `checkpoint.jsonl` loads to one entry: the
   root.
7. **Errors.** A directory whose listing fails is not marked complete, so a resume visits it again.

## 8. Qualification

This changes traversal, and later recovery, so it needs a hardware qualification before release
(MAINTAINERS.md, section 4). Scenarios for the maintainers to request, on the exact candidate:

1. `check` with `--state-dir` on the read-only qualification tree; stop at about 30% with the STOP
   file; resume; compare the last record per path with a single uninterrupted run of the same
   candidate.
2. The same with Ctrl+C.
3. Kill the process (Task Manager) at about 50%, then `--resume`. Expect no lost subtree; repeated
   records are allowed.
4. Record the size of `checkpoint.jsonl` and `records.jsonl` for the tree.

Report passed, failed and skipped cases separately.

## 9. Done means

- Options, files, exit code 3 and the tests in section 7 are in one PR, with `smb/README.md` updated
  (commands, the state dir, exit codes).
- The qualification in section 8 is requested and reported as pending until it passes.
- `DESIGN-write-path.md`, section 3.4, gets a line that points here as the as-built mechanism for
  `check`, to be reused by `apply`.

## As built

- 5.2 step 3 differs: a resume does not load counts from the last `status.json` (objects re-checked
  in an incomplete directory would be counted twice). Each `checkpoint.jsonl` line carries the
  counts of its whole subtree (`objects`, `outcomes`, `forms`, `sacl_forms`); a resume seeds the
  totals from the sum of the outermost entries, a pruned subtree's counts join its parent's, and
  the root's final line holds the whole run's counts. The final counts equal a single
  uninterrupted run's.
- A stop request that arrives after the walk already reached everything is a completed run
  (exit 0), not a stopped one: there is nothing to resume.
- Segments record `pid` and `process_start` (5.2's second-process refusal), and `--resume` of a
  completed run is refused with exit 2.
- Measured on a generated fake tree of 2,254,421 objects (100 files per directory, three
  subdirectory levels): after a completed run `records.jsonl` was 210,948,298 bytes and
  `checkpoint.jsonl` 64,853 bytes (343 lines, one per completed subtree at an interval flush; the
  load keeps the outermost); after a stop at about half, `records.jsonl` was 104,990,746 bytes and
  `checkpoint.jsonl` 63,518 bytes (336 lines).
