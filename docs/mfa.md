# Administrator TOTP MFA

This feature protects the **opnSentral application login**. It does not
change authentication on managed OPNsense firewalls or the agent API.

## Enrollment

1. Sign in using your configured opnSentral administrator username and password.
2. Open **Application Settings → Multi-factor authentication → Configure MFA**.
3. Enter the administrator password to start enrollment.
4. Scan the locally generated QR code using an authenticator such as KeePassXC,
   or enter the displayed setup key manually. Settings are TOTP / SHA-1 /
   6 digits / 30 seconds.
5. Enter the current authenticator code and administrator password to activate MFA.
6. Save the **ten recovery codes** offline before leaving the confirmation page.
   Each can be used only once. Their original values cannot be retrieved later.

MFA is disabled by default when upgrading existing installations. Once enabled,
opnSentral invalidates pre-enrollment administrator sessions.

## Login

After successful username/password authentication, opnSentral asks for a TOTP
code or an unused one-time recovery code. Password entry alone does not
establish an authenticated administrator session.

**Option 2:** while MFA is enabled, the **interactive `ADMIN_API_KEY` login
is disabled**. The key is not deleted or rotated; the existing alternate login
form is restored if MFA is later disabled. The API credentials stored for
managed OPNsense firewalls and the opnSentral agent credentials are not changed.

An authenticator device's clock must be reasonably accurate. The server accepts
a small timing tolerance and prevents reuse of a previously accepted TOTP step.
Repeated incorrect MFA attempts temporarily block further challenges.

## Disable MFA

From **Application Settings → Multi-factor authentication**, enter the
administrator password and a fresh TOTP or unused recovery code. Disabling MFA
rotates the session generation and invalidates other previously authenticated
sessions.

## Recovery and backups

Keep the recovery codes somewhere separate from your primary authenticator.
If the authenticator and **all** recovery codes are lost, normal browser login
cannot reset the second factor. An operator-controlled recovery procedure is
required; this feature does not provide a password-only bypass.

The TOTP secret is encrypted using the existing `APP_KEY`. **Preserve that
key when migrating or restoring** opnSentral, otherwise encrypted MFA data
will not decrypt. Store backups securely.

Use HTTPS and secure session cookies in production. QR generation happens inside
the opnSentral container using local `qrencode`; the setup secret is not sent
to an external QR service.

## Verification

The dedicated PR workflow builds a disposable Docker image and runs:
- RFC 6238 TOTP vector and replay tests;
- enrollment, session, and one-time recovery-code tests;
- live HTTP login tests for old sessions and API-key bypass;
- a check that local QR generation yields a PNG.

These checks do not constitute a penetration test against a production host.
