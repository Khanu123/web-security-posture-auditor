# Web Security Posture Report

Target: `https://demo.local`

Grade: **F**

| Severity | Finding | Evidence | Recommendation |
| --- | --- | --- | --- |
| MEDIUM | Missing strict-transport-security | Header not present | Add HSTS to enforce HTTPS for repeat visitors. |
| MEDIUM | Missing x-frame-options | Header not present | Add X-Frame-Options or frame-ancestors to reduce clickjacking risk. |
| MEDIUM | Weak Content Security Policy | default-src * 'unsafe-inline' | Remove wildcards and unsafe inline script allowances where possible. |
| LOW | Server version disclosure | nginx/1.18.0 | Avoid exposing exact server versions in HTTP headers. |
