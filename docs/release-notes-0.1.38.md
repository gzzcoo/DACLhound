# DACLhound 0.1.38

## Graph exploration

- Add Home to return from an object-focused view to the full graph, and keep Reset scoped to the current graph view.
- Keep manual node movement in Focus temporary; restore the saved full-graph positions when returning Home.
- Keep object focus active when clicking empty graph space.
- Refine focused graph context so expanded Members, Member Of, Outbound Object Control, and Inbound Object Control sections determine which relationships are shown.
- Improve membership hierarchy and reduce unrelated membership edges in ACL-focused views.

## ACL details

- Group outbound permissions by target and show each right clearly, including multiple rights on one object.
- Add technique-specific References panels with relevant DACL and Kerberos delegation resources.
- Improve ACL member lists with clickable principals, clearer alignment, and consistent icons.
- Fix spacing and clipping in Description, Permission details, Linux abuse, and member sections.

## Interface

- Keep Search expanded by default and refine the Home and graph layout controls.
- Improve property row contrast, panel alignment, and graph readability in both themes.
