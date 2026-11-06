# DACLhound

DACLhound collects Active Directory security descriptors over LDAP and turns the results into a graph you can inspect in a browser. The collector uses bloodyAD as a Python library; it does not run the `bloodyAD` command. Impacket's Python library handles password-based Kerberos TGT requests, passing the ticket in memory to bloodyAD.

It is primarily intended for Hack The Box (HTB) and similar hands-on labs, and works best with lab-sized or otherwise moderate Active Directory environments. It is not designed or performance-tested for very large enterprise domains.

Unlike BloodHound CE's modeled graph edges, DACLhound preserves the collected DACL details and exposes individual `Write-Property` rights by attribute (for example, `WriteLogonHours` or `WriteUserAccountControl`, etc.). This helps inspect the specific property and ACE behind a relationship.

## Development status

DACLhound is still under active development. I plan to update it daily as I continue testing it, fixing bugs, and improving the results. You may encounter issues, and feedback or bug reports are welcome.

![DACLhound graph example](https://raw.githubusercontent.com/gzzcoo/DACLhound/main/DACLhound/DACLhound.png)

## Demo

https://github.com/user-attachments/assets/62a531d9-c3f0-47d3-aab0-d7fef8db28d1

The demo walks through collecting a domain and opening the graph viewer. It also shows selecting an object to focus on its permission paths, hiding objects, and setting start and end nodes to reveal a path.

## Install

Python 3.10 or newer is required.

```sh
pipx install DACLhound
```

Upgrade later with:

```sh
pipx upgrade DACLhound
```

## Collect a graph

```sh
DACLhound.py collect --host $FQDN -d $DOMAIN -u 'user' -p 'password' --dc-ip $IP --output $DOMAIN.json
```

The collector is read-only. By default it collects users, groups, computers, OUs, containers, GPOs, the domain, and ADCS data. Use `--types` to limit directory object types:

```sh
DACLhound.py collect --host $FQDN -d $DOMAIN -u 'user' -p 'password' --types users,groups --output users-and-groups.json
```

Use `--no-adcs` to skip ADCS collection. The normalized graph is written to `--output`. Add `--raw-output` to keep the collector's raw entries as well.

By default, `collect` tries LDAP first and retries through DACLhound's native ADWS transport when LDAP cannot connect. To force ADWS, use `--transport adws`; use `--transport ldap` to require LDAP. ADWS uses TCP port 9389 and supports NTLM and Kerberos authentication. Kerberos uses the selected ccache or obtains a ticket in memory with Impacket; DACLhound does not launch another collector or authentication tool. LDAPS applies to LDAP collection. The ADWS collector reads security descriptors directly and resolves schema GUIDs so attribute-scoped `Write-Property` rights remain visible.

LDAP visibility depends on the account used for collection. If you have multiple accounts with different directory permissions, collect the domain with each one; their results may reveal additional objects or ACLs. Load the resulting JSON files together in the graph viewer, or pass them together to `analyze` to combine their data.

## Analyze saved graphs

Run a quick console triage of saved graphs without opening the web viewer. `analyze` reports domain context, Domain Admins, effective permission paths, Kerberos roasting, delegations, ADCS findings, trusts, and other useful relationships. You can analyze several domains together; duplicate objects and relationships are combined:

```sh
DACLhound.py analyze result.json
DACLhound.py analyze result.json result2.json
DACLhound.py analyze result.json --from-user 'alice'
```

By default, `analyze` traces effective permission paths from collected users, resolves trustees by SID across all supplied JSON files, and groups paths that share a trustee group. It also reports direct rights, domain membership, delegation, roasting, ADCS, and GPO link findings in prioritized sections. Use `--from-user` to focus the paths on one account. Output is colorized by default; use `--color never` to disable colors. This is a quick way to review findings from the terminal when you do not need the web viewer.

## Authentication

### NTLM password

```sh
DACLhound.py collect --host $FQDN -d $DOMAIN -u 'user' -p 'password' --dc-ip $IP -o $DOMAIN.json
```

### NTLM pass-the-hash

Use `LMHASH:NTHASH`; if you only have the NT hash, leave the LM field empty:

```sh
DACLhound.py collect --host $FQDN -d $DOMAIN -u 'user' -hashes ':<NTHASH>' --dc-ip $IP -o $DOMAIN.json
```

### Kerberos

Kerberos supports a password, pass-the-hash, or an existing ccache. When using a
ccache, `-u` is optional; the identity is taken from the ticket. `-no-pass` is
an explicit flag for ccache authentication.

**Password:**

```sh
DACLhound.py collect --host $FQDN -d $DOMAIN -u 'user' -p '<password>' -k --dc-ip $IP -o $DOMAIN.json
```

**Pass-the-hash (NT hash used as the Kerberos RC4 key):**

```sh
DACLhound.py collect --host $FQDN -d $DOMAIN -u 'user' -hashes '<LMHASH>:<NTHASH>' -k --dc-ip $IP -o $DOMAIN.json
```

If only the NT hash is available, use `-hashes '<NTHASH>'`.

**Existing ccache:**

```sh
# Use the current KRB5CCNAME
DACLhound.py collect --host $FQDN -d $DOMAIN -k -no-pass --dc-ip $IP -o DOMAIN.json

# Or provide a ccache file directly
DACLhound.py collect --host $FQDN -d $DOMAIN -k user.ccache -no-pass --dc-ip $IP -o $DOMAIN.json
```

An AES key enables Kerberos automatically: use `-aesKey '<AESKEY>'` (with `-u`). Add `-s` to use LDAPS.

## Open the graph

Run the viewer in the foreground and stop it with `Ctrl+C`:

```sh
DACLhound.py graph --input $DOMAIN.json
```

Or run it in the background:

```sh
DACLhound.py graph start
DACLhound.py graph start --input $DOMAIN.json
DACLhound.py graph status
DACLhound.py graph stop
```

The server listens on `127.0.0.1:8765` by default. Uploaded JSON files stay in memory while the server is running and are discarded when it stops. Use `--bind` and `--port` to change the listener. Run `DACLhound.py collect --help` or `DACLhound.py graph --help` for all options.

## License

MIT. See [LICENSE](LICENSE).
