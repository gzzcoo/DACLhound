# DACLhound 0.1.24

## Highlights

- Added a native ADWS collector. Collection can use LDAP or ADWS; automatic mode tries LDAP first and falls back to ADWS when LDAP cannot connect. Either transport can be selected explicitly.
- Added ADWS authentication support for NTLM and Kerberos, including use of an existing Kerberos cache and in-memory ticket acquisition.
- Expanded ADWS DACL parsing and schema GUID resolution so object-scoped rights such as property writes, validated writes, password reset, self-membership, and tombstone restoration are represented in the normalized graph.
- Added collection of domain trusts, ADCS objects and findings, and template enrollment ACLs through ADWS.
- Improved graph visibility for ACL-related group memberships and fixed selection behavior when focusing a member that had been hidden by the membership filter.
- Kept phone and mail property-set writes visible in the graph by default, consistently for LDAP and ADWS.
- Improved console analysis output, trustee SID resolution, delegation and Kerberos roasting summaries, and documentation for analyzing multiple datasets and collecting with different accounts.

## Compatibility

- Python 3.10 or later.
- LDAP remains supported. ADWS is available with `--transport adws`; the default `--transport auto` falls back to ADWS when LDAP cannot connect.
