# 📘 Playbook 1: Suspicious Login from Impossible Travel Location

**Alert Source:** Azure AD Identity Protection / M365 Defender  
**Detection Name:** "Risky Sign-In" / "Impossible Travel"

---

## 🔍 Triage Steps

- Verify user identity via internal comms (/Teams/email).
- Check if user is traveling (check HR travel logs if available).
- Confirm location using IP geolocation.

---

## 🔎 Investigation (Splunk)

```spl
index=o365 sourcetype="o365:azuread" Operation=SignInLogs
| search UserPrincipalName="user@example.com"
| stats count by Location, IPAddress, DeviceDetail

## 🛠️ Response Actions
If confirmed malicious:

- Reset password.

- Disable session tokens.

Add IP to blocklist (via conditional access or firewall).

Notify user and document actions.
