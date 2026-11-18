# DACLhound 0.1.36

## Improvements

- Collect and display each group's `groupType` value with its security/distribution and scope description.
- Show direct group members and nested group memberships in the graph and object details, while keeping hidden objects visible in relationship lists.
- Add an object-focus action to isolate a selected object and its relevant relationships.
- Improve the object details panel, membership navigation, and graph interaction layout.
- Refine inbound object-control details to emphasize actionable permissions and group trustees.

## Bug Fixes

- Exclude `INHERIT_ONLY` ACEs from direct effective-control edges.
- Keep group members in the details panel when they are visually hidden from the graph.
