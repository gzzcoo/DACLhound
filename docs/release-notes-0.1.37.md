# DACLhound 0.1.37

This release consolidates the improvements shipped since 0.1.35.

## Active Directory analysis

- Add per-finding Certipy Wiki references for AD CS ESC techniques.
- Add a Domain Groups query, excluding Domain Users and Domain Computers, and show group members.
- Display collected `groupType` values with their scope and security/distribution meaning.
- Add Linux abuse guidance for resource-based constrained delegation, including SPN-less RBCD references.
- Improve ReadGMSAPassword command examples for group trustees and shorten WriteUserAccountControl to WriteUAC.
- Show user logon script paths in object details.

## Graph and object details

- Show direct and nested group membership in object details, with clickable group navigation.
- Keep relationship lists complete when objects are hidden from the graph; show owned members in graph context.
- Add object focus to isolate a selected object and relevant relationships.
- Refine inbound and outbound object-control lists to emphasize actionable ACLs and group trustees, and group multiple permissions by target.
- Improve the details panel, membership navigation, and graph interactions.

## Bug fixes and visual improvements

- Exclude `INHERIT_ONLY` ACEs from direct effective-control edges.
- Preserve hidden group members in relationship lists.
- Improve graph label clarity in the light theme.
- Add shell syntax coloring to Linux abuse command blocks.
