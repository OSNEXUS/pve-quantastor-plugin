# Contributing

## Prerequisites

- Perl 5.30+
- `libwww-perl`, `liburi-perl` (LWP + URI::Escape)
- `open-iscsi` (for iSCSI tests on a real host)
- A QuantaStor appliance or VM for integration testing

## Running the test suite before submitting

```bash
./t/run_tests.sh
```

All 157 unit tests must pass with no warnings. New functionality should include corresponding
tests in the relevant test file (`t/01-api-client.t`, `t/02-iscsi-manager.t`, or `t/04-plugin.t`).
`t/05-no-ticket-refs.t` guards the documentation rule below.

- Do not reference internal ticket IDs, issue-tracker links, or working dates in tracked
  files — describe the behavior and the release version instead
  (`t/05-no-ticket-refs.t` enforces this).

## Adding a new QuantaStor API method

1. Add the method to `src/perl5/PVE/Storage/QuantaStor/APIClient.pm` following the existing pattern
2. Add unit tests covering the happy path, parameter validation, and at least one error path
3. Update the method table in [`src/README.md`](src/README.md)

## Roadmap

### Migration tooling

For deployments still running the archived patch-based alpha:

- Script to enumerate volumes under the old `zfs`/`quantastor` storage entry
- Move VM disk associations to the new `quantastor` storage type non-destructively
- Restore pristine PVE files: `apt reinstall pve-storage pve-manager`
