# DACLhound 0.1.40

## SCCM / MECM inventory

- Add optional `--sccm` collection for published sites, management points, potential PXE distribution points, SCCM/MECM principals, and computer roles.
- Resolve discovered computer names through the domain controller's DNS and profile SMB authentication, signing, shares, and selected TCP indicators.
- Add SCCM site, SMS Provider, and site database objects to the graph, with grouped role relationships and conditional site-takeover relay paths.
- Add SCCM collection results to the command summary and reuse host-check timeout settings.

## JSON organization

- Add `daclhound json split` to export per-object-type JSON files, a shared `edges.json`, and a manifest, optionally packaged as a ZIP for manual analysis.

## Interactive update prompt

- Check PyPI for a newer release at interactive CLI startup and offer **Update now**, **Skip**, or **Skip until next version**.
- Fix the PyPI JSON endpoint so update checks resolve the package's canonical project name.
- Keep update prompts disabled in non-interactive runs and provide `DACLHOUND_NO_UPDATE_CHECK=1` to disable them explicitly.

## Graph and viewer

- Improve SCCM graph relationships and details, including grouped site roles, SMS Provider and site database nodes, and conditional relay edges.
- Keep SCCM inventory edges out of ACL pathfinding while allowing SCCM attack transitions to participate.
- Add a filter to hide SCCM-related graph data.

## Licensing and documentation

- Use GPL-3.0-only project licensing.
- Add the DACLhound Viewer and SCCM/MECM Wiki link to the README.
