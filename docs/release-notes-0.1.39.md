# DACLhound 0.1.39

## Themes and graph controls

- Add a Red theme alongside Dark and Light, with consistent colors across the graph, navigation, search, filters, details, and dialogs. Dark remains the default; the selected theme is remembered.
- Remove object hover tooltips and hover-only graph highlighting to keep the graph uncluttered while preserving click and drag interactions.
- Keep the visible-object search and hidden-object picker mutually exclusive so their panels do not overlap.

## Active Directory analysis

- Add a **DCs vulnerable to NTLM relay to LDAP attacks** query using collected LDAP signing and channel-binding policy values.
- Extend `--host-checks` to collect LDAP signing and channel-binding policy from domain controllers over Remote Registry RPC. Unavailable registry values remain unknown instead of being inferred.
- Show the built-in Domain Controllers group's DCSync rights on the domain as a DCSync relationship, with NetExec and Impacket command examples that fill in the domain, DC account, and FQDN from the graph. The NT hash and DC IP remain editable placeholders.
- Add The Hacker Recipes' DCSync reference.
- Represent unconstrained-delegation TGT coercion as a `CoerceToTGT` relationship to the domain.

## Bug fixes and interface refinements

- Fix clipping of dataset status markers in the dataset manager.
- Refine details-panel layout and theme colors, including the object heading and count badges.
- Improve graph-theme consistency for search, hidden objects, pathfinding, saved queries, and object details.
