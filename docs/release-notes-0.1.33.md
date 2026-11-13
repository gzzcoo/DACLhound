# DACLhound 0.1.33

## Bug Fixes

- Collect effective memberships in BUILTIN Administrators, Domain Admins, and Enterprise Admins so non-default accounts and their important group paths are visible even when `memberOf` is empty.
- Keep the default Administrator account's routine Domain Admins and Enterprise Admins memberships out of the overview when they add no non-default members.
- Hide the misleading Cert Publishers `GENERIC_ALL` relationship to the AIA container in the graph overview.
