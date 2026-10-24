# FinMind privacy workflow

The account privacy endpoints are authenticated with the existing JWT access token.

## Export

`GET /auth/me/export` returns a ZIP download containing `account.json`. The package
includes the account profile and all user-scoped categories, expenses, recurring
expenses, bills, reminders, ad impressions, subscriptions, and audit records. Password
hashes are intentionally excluded. Every export creates an `account.export` audit row.

## Permanent deletion

`DELETE /auth/me` requires a JSON body with the current `password` and an exact
`confirm_email` matching the account email. The server writes an `account.delete`
audit tombstone, removes every user-owned row, deletes the user, and revokes matching
refresh sessions in Redis. The endpoint returns only after the database transaction
commits; it cannot be undone.

The test suite covers ZIP contents, password-hash exclusion, audit entries,
confirmation failures, and post-deletion access.
