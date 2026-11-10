# DACLhound 0.1.28

## Highlights

- Added object details for creation time, password last set, User Account Control, last logon, and group memberships.
- Removed the redundant “Active Directory” prefix from object type labels.
- Added graph quick views for delegations, AS-REP roastable accounts, Kerberoastable accounts, and objects with `adminCount=1`. Quick views show the matching findings without unrelated ACLs and report when there are no results.
- Improved group membership context: memberships of already visible principals are shown when their groups have relevant ACLs. Owned principals also reveal these relationships automatically.
- Persisted Owned markings across browser reloads.
- Filtered well-known SIDs such as `S-1-5-11` and `S-1-5-17` out of Foreign Security Principal objects and resolve them to readable trustee names.
- Derive the graph domain and default output filename from the collected directory naming context, including cross-forest collection where the authentication domain differs from the target domain.
