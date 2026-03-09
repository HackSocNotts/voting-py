# Election System

Python instant-runoff voting system inspired by [HackSocNotts/voting](https://github.com/HackSocNotts/voting).

## Services

| Port  | Service      |
|-------|--------------|
| 10000 | Registration |
| 10001 | Ballot       |
| 10002 | Tally/Admin  |

- FastAPI services backed by PostgreSQL 
- Each service has its own DB role with only the permissions it needs 
	- for example, the tally service cannot write ballots, the ballot service cannot touch members.
- Should be reverse proxied behind /register, /ballot, and /admin:
```
handle /register/* {
    uri strip_prefix /register
    reverse_proxy elections-registration-1:8000
}
handle /ballot/* {
    uri strip_prefix /ballot
    reverse_proxy elections-ballot-1:8000
}
handle /admin/* {
    uri strip_prefix /admin
    reverse_proxy elections-tally-1:8000
}
```

## Running an Election

1. **Setup roles**: `/admin/setup`
2. **Import members**: `/register/import-members` (paste SUMS members list, 8-digit IDs extracted automatically)
3. **Start**: `/admin/start` (enter admin secret + duration)
4. **Members register and vote**: `/register -> /ballot?token=XXXXXX`
5. **Close and reveal results**: `/admin` (click reveal once timer expires)
6. **Reset for next election**: `/admin/start`

## Security

**Service isolation**: three separate processes, each with a dedicated Postgres role. Permissions are granted at the database level (RBAC), not enforced in application code. For example, the tally service holds `SELECT` only on ballots and cannot write votes under any circumstances.

**Token integrity**: the registration service signs each ballot token with `HMAC-SHA256(random, TOKEN_SECRET)`. The ballot service verifies this independently at submission time with no runtime communication between services. Tokens are single-use.

**Vote integrity**: each submitted ballot is signed with `HMAC-SHA256(canonical_votes_json, TOKEN_SECRET)` and stored alongside the votes as `vote_hmac`. The tally service verifies every ballot's signature before counting. Any ballot that fails verification is excluded from the tally and logged.

**Double-vote prevention**: the registration service records issued ballots in `members_voted`. A student ID that has already been issued a ballot cannot receive another, enforced at the DB level by a `unique` constraint.


## Original Project

Go implementation: [HackSocNotts/voting](https://github.com/HackSocNotts/voting)