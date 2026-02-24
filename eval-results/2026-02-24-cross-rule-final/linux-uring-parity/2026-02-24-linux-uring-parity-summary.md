# Linux uring Parity Validation Summary

Date: 2026-02-24
Environment: Docker Linux container (`rust:1.90`) on host `Darwin arm64`

## Result

Linux uring parity checks passed when run in a privileged container (required for `io_uring` syscalls under Docker seccomp defaults).

## Tests executed (pass)

- `scheduler::local_fs_uring::tests::uring_open_stat_parity_with_blocking`
- `scheduler::local_fs_uring::tests::uring_cross_rule_mode_uses_hash_aware_winner_pass`

## Notes

- Non-privileged container run failed with `BrokenPipe` / `io threads stopped`, consistent with restricted `io_uring` syscall access.
- Privileged run succeeded for both target parity tests.

## Logs

Raw container logs were generated during execution but are intentionally not
tracked in git. Re-run commands from the main decision artifact to reproduce.
