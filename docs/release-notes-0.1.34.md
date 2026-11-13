# DACLhound 0.1.34

## Bug Fixes

- Fix LDAP collection failures on Active Directory by reading the computed `tokenGroups` attributes with per-user BASE searches instead of including them in subtree searches.
- Apply the same BASE-scope handling to the ADWS transport while keeping bulk enumeration as subtree searches.
