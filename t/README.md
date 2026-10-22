# Running the tests

## Unit tests (no appliance required)

```bash
cd qs-pve-plugin
./t/run_tests.sh
```

Requires: `perl`, `libwww-perl`, `liburi-perl` (`JSON::PP` and `File::Temp` are included in Perl core)

```bash
# Install on Debian/Ubuntu/PVE host
apt install libwww-perl liburi-perl
```

## Integration tests (live QuantaStor appliance)

```bash
export QS_HOST=10.0.0.1
export QS_PASSWORD=mysecret
export QS_POOL=test-pool      # Use a dedicated test pool — not production

./t/run_tests.sh --all
```

> Integration tests **create and delete real volumes** on the appliance. Always target a
> dedicated test pool.

| Variable | Required | Default | Description |
|---|---|---|---|
| `QS_HOST` | yes | — | QuantaStor appliance IP or hostname |
| `QS_PASSWORD` | yes | — | API password |
| `QS_POOL` | yes | — | Storage pool name or UUID |
| `QS_USER` | no | `admin` | API username |
| `QS_PORTAL` | no | `QS_HOST` | iSCSI portal address if different from API host |
| `QS_SSL` | no | `0` | Set to `1` to enable SSL certificate verification |
| `QS_CA_CERT` | no | — | Path to CA cert file for SSL verification |

## Verbose output

```bash
./t/run_tests.sh --verbose
```
