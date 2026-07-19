# Web Security Posture Report

Target: `https://demo.local`

Grade: **F**

| Severity | Finding | Evidence | Recommendation |
| --- | --- | --- | --- |
| MEDIUM | Missing strict-transport-security | Header not present | Add HSTS to enforce HTTPS for repeat visitors. |
| MEDIUM | Missing x-frame-options | Header not present | Add X-Frame-Options or frame-ancestors to reduce clickjacking risk. |
| MEDIUM | Missing x-content-type-options | Header not present | Add X-Content-Type-Options: nosniff. |
| MEDIUM | Missing referrer-policy | Header not present | Add a Referrer-Policy to limit sensitive URL leakage. |
| MEDIUM | Weak Content Security Policy | default-src * 'unsafe-inline' | Remove wildcards and unsafe inline script allowances where possible. |
| LOW | CSP does not define object-src | default-src * 'unsafe-inline' | Set object-src 'none' unless plugins are explicitly required. |
| LOW | CSP does not define base-uri | default-src * 'unsafe-inline' | Set base-uri 'self' or 'none' to restrict base URL injection. |
| HIGH | Cookie session lacks Secure | session=synthetic-value; Path=/ | Add the Secure attribute to session and sensitive cookies. |
| MEDIUM | Cookie session lacks HttpOnly | session=synthetic-value; Path=/ | Add HttpOnly unless client-side script access is required. |
| MEDIUM | Cookie session lacks SameSite | session=synthetic-value; Path=/ | Set SameSite=Lax or Strict unless cross-site use is required. |
| HIGH | Credentialed CORS uses wildcard origin | Access-Control-Allow-Origin=* and credentials=true | Use an explicit allow-list and never combine credentials with a wildcard origin. |
| LOW | Server version disclosure | nginx/1.18.0 | Avoid exposing exact server versions in HTTP headers. |
