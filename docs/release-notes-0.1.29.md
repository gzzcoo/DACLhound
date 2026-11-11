# DACLhound 0.1.29

## Highlights

- Fixed path highlighting so effective paths retain the `MemberOf` edge that connects a principal to the group supplying its permissions.
- Resolve Foreign Security Principal nodes to a uniquely matching directory object by SID when that object is present in the loaded datasets. Edges are redirected to the resolved object; unmatched or ambiguous SIDs remain visible as Foreign Security Principals.
