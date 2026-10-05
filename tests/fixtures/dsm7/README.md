Hand-written DSM 7 responses for the alarm states a healthy NAS never shows
(a crashed disk, a degraded or rebuilding pool, a data scrub, a pending update).

The storage files copy the shape of a `SYNO.Storage.CGI.Storage load_info`
reply recorded from a DS920+ on DSM 7.4.1 with `scripts/capture-fixtures.sh`:
the same field names, nesting and strings-vs-numbers, including the
`progress { percent, step, ... }` block DSM fills in during an operation.
Every value is made up. `update_*.json` follow the flat shape that NAS
answered `SYNO.Core.Upgrade.Server check` with (`{"available": false}`); the
`version` field of a pending update has not been seen from a real NAS yet.

The recordings themselves stay out of git (see `.gitignore`): even redacted,
they describe one real NAS.
