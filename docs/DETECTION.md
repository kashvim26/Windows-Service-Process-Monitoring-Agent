# Detection rules and response notes

The collector takes a point-in-time process inventory, resolves PPID against that inventory, and applies the configured rules in `config/rules.json`. Every detection includes a category, severity, timestamp when ingested, endpoint, and selected process or service evidence. The API stores alert history for the configured retention period.

| Category | Trigger | Default severity | Suggested triage |
|---|---|---:|---|
| `parent_child` | Configured parent/child executable pair | High or medium per rule | Confirm the user's activity and inspect the parent and child paths, account, and start time. |
| `writable_path` | Process image path contains a configured writable-directory marker | Medium | Verify publisher and origin; these directories are abused but also contain legitimate installers and apps. |
| `deny_list` | Image name appears in the configured deny list | High | Confirm whether the process is approved; validate the path and signature with endpoint tools. |
| `service_path` | Automatic service image path contains a configured risky marker | High | Inspect service owner, binary ACLs, service ACLs, creation/change time, and change ticket. |
| `new_service` | Automatic service appears after baseline initialization | Medium | Determine install source and owner; validate binary signature and service permissions. |
| `service_change` | A service's collected configuration hash differs from its stored baseline | High | Compare binary path, start mode, account, and state to approved changes. |

The first observed services are baselined. Newly observed automatic services are flagged on first observation. The baseline currently keeps service names and hashes for the lifetime of the database; remove the matching database row only as part of a documented baseline reset. A whole-system process list is sampled, so very short-lived processes can be missed. A PPID can also refer to an exited process and is omitted if that parent is not in the same snapshot.

## Safe validation

Use a dedicated lab VM with disposable data. You can directly unit exercise `analyze` with synthetic process dictionaries without launching suspicious programs or changing the service registry. Do not test against a production endpoint. Tune exceptions in version control and record why they exist.

## Roadmap for production use

Add signed binary verification via Windows trust APIs, service and executable ACL inspection, event-driven process start collection, endpoint-specific credentials, alert deduplication and acknowledgement, a managed relational database, authenticated analyst accounts, and formal log retention controls before fleet deployment.
