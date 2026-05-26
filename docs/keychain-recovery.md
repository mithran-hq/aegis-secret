# Keychain Recovery

Aegis Secret stores secrets in the macOS Keychain under the signed app's
keychain access group. If a local build or release was signed with a different
access-group prefix, existing secrets can remain intact but invisible to the
current app.

The recovery command compares a historical signed Aegis binary with the current
signed Aegis binary. It reports signing identity, keychain access group, counts,
and key names only.

```bash
aegis-secret recovery diagnose \
  --source-app "/path/to/old/Aegis Secret.app/Contents/MacOS/aegis-secret"
```

The diagnostic does not read secret values.

To copy every source key that is missing from the current app:

```bash
aegis-secret recovery migrate \
  --source-app "/path/to/old/Aegis Secret.app/Contents/MacOS/aegis-secret" \
  --all
```

To copy one key:

```bash
aegis-secret recovery migrate \
  --source-app "/path/to/old/Aegis Secret.app/Contents/MacOS/aegis-secret" \
  --key OPENAI_API_KEY
```

Existing target keys are skipped unless `--overwrite` is supplied.

During migration, the source app reads each selected secret through its own
Keychain entitlement and passes the bytes directly to the current app process.
The command prints key names, counts, and access groups, but it does not print
secret values.

Recovery fails closed unless both binaries prove:

- an Apple team identifier;
- an Aegis Secret application identifier;
- an Aegis Secret keychain access group;
- the same Apple team identifier on source and target.

If no signed Aegis binary remains for a historical access group, Aegis cannot
read that namespace. That is the Keychain entitlement boundary working as
designed.
