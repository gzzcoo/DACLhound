# DACLhound 0.1.35

## Improvements

- Add per-ESC Certipy Wiki links to AD CS finding details.
- Add a Domain Groups query, excluding Domain Users and Domain Computers, with member details when a group is selected.
- Show Linux abuse guidance for resource-based constrained delegation (RBCD), including a getST.py example and an SPN-less RBCD reference.
- Show logon script paths in user profiles.
- Shorten the WriteUserAccountControl label to WriteUAC.

## Bug Fixes

- Use a member account, when available, in ReadGMSAPassword command examples for group trustees; otherwise show a user placeholder.
