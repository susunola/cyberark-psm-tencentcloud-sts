# IIS proxy boundary

The bridge listens on `127.0.0.1:8765` and rejects any peer that is not loopback. That is not authentication. The reverse proxy is.

Required behavior:

1. Anonymous authentication off. Windows authentication on. Restrict the site to the PSM session identities that are allowed to open this platform.
2. Delete inbound `X-PSM-Bridge-Key` and `X-PSM-Authenticated-User` before the request is forwarded. A browser that can set those headers must not be able to keep them.
3. Set `X-PSM-Bridge-Key` to the same value as `PSM_TC_PROXY_KEY`. Set `X-PSM-Authenticated-User` to the Windows account the proxy actually authenticated. Do not copy either value from the client.
4. Forward the path and the POST body to `http://127.0.0.1:8765`. Preserve the browser-side HTTPS name. Do not rewrite the peer address into `X-Forwarded-For` and expect the bridge to trust it.
5. Do not log request bodies, cookies, `Location`, or the handoff HTML. The POST handoff still contains a temporary token in the response body.
6. Keep the proxy key in a protected config store, not in this repository and not in a world-readable `web.config`.

`deploy/web.config.example` only shows the authentication and header-strip shape. ARR installation, certificates, and the secret server variable are environment steps.

Liveness is `GET /healthz` with the proxy key and no user header. `/` and `/connect` require the authenticated user header.
