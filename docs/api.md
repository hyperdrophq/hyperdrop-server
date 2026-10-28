# HyperDrop server HTTP API

This is the reference for the HTTP API of `hyperdrop-server`: what a client sends, what the
server answers, and what it refuses. It is written for someone building a client or auditing the
server. The server's configuration is in [`docs/configuration.md`](configuration.md) and its
security model in [`docs/security.md`](security.md).

The API has two halves. The **authenticated API** under `/api/` is what client apps use: every
call carries a bearer token minted by signing in. The **public routes** (`/share/…`, `/view/…`,
`/download/…`, `/receive/…` and the rest) are what a link's recipient opens in a browser: they
take no account, and the share's random id is the capability.

Every route the server registers is listed in [§ Route index](#route-index) at the end, and every
machine-readable error code in [§ Error codes](#error-codes).

## Contents

- [Conventions](#conventions)
- [Versions and the client header](#versions-and-the-client-header)
- [Authentication](#authentication)
- [Your account](#your-account)
- [Accounts (admin)](#accounts-admin)
- [Shares](#shares)
- [Uploads](#uploads)
- [Files and folders in a share](#files-and-folders-in-a-share)
- [Previews and gallery records](#previews-and-gallery-records)
- [Receive Inboxes](#receive-inboxes)
- [Linked shares](#linked-shares)
- [Live shares](#live-shares)
- [Server administration](#server-administration)
- [Push notifications](#push-notifications)
- [Public routes](#public-routes)
- [Error codes](#error-codes)
- [Route index](#route-index)

## Conventions

**Hosts.** A server serves one domain. Its pages, the password form and the API answer on
`<domain>`; uploaded bytes answer only on `files.<domain>`, a separate browser origin (see
[§ Two origins](#two-origins)). The `/api/` surface answers on any host the server is reached by,
including its bare IP address. A call carries its bearer token, so a page on another origin has
no more power over it than any other HTTP client. The one cookie `/api/` reads is the web
client's session, `__Host-hd_web`, and only on the app host, from the web client's own page
(`X-HyperDrop-Client` naming the web platform, a same-origin fetch), on the JSON routes
`server/internal/api/cookieroutes.go` lists; every other route refuses it, and no other cookie is
read.

**JSON.** Request and response bodies are JSON (`Content-Type: application/json`) unless a route
says otherwise. Times are RFC 3339 in UTC. A field marked *omitted when empty* is absent rather
than `false`, `0`, `""` or `[]`, and its absence means exactly that value.

**Strict request bodies.** Every JSON request body is decoded strictly: a field the route does not
know, or anything after the JSON value, is a `400` with the message `invalid JSON: this server does
not know the field "<name>"` (or `invalid JSON`). A body larger than the route's cap answers the
same `400 invalid JSON`. This is what makes a newer client's new field a loud refusal on an older
server instead of a silently dropped one; see [§ Versions](#versions-and-the-client-header).

**Errors.** A refusal is `{"error":"<sentence>"}`, plus `"code":"<code>"` when the condition is one
a client words or acts on specially. Branch on the status and the `code`, never on the sentence.
The codes are listed in [§ Error codes](#error-codes). A failure the server did not expect is a
`500` whose body is `{"error":"internal error (ref <8 hex>)"}`: the cause goes to the server's log
under that reference and never into the response, since it can name a table, a driver error or a
path on the data volume. A database that cannot answer is a `500` on every route, including sign-in
and token checks, never a `401`: a fault must not read as a revoked token or a wrong password.

**Response compression.** The authenticated `GET` routes that answer JSON lists (`GET /api/me`, the
share list and share reads, the change feed, the users list, token and source listings and the
rest of the routes marked *compressed* below) and the server's public pages (the share page, the
status poll, the Receive Inbox page, the front page and the not-found page) honour
`Accept-Encoding`: `zstd` when offered, else `gzip`, never a coding offered with `q=0`, and never
for a request carrying `Range`. A compressed response has `Vary: Accept-Encoding` and no
`Content-Length`. `/view` and `/site` negotiate for text files only (see
[§ Public routes](#public-routes)); `/download` and `/zip` are never content-encoded, so their
`Content-Length` is exact.

**Request bodies are judged by stalls, not by time.** The server sets no whole-request timeout,
since an upload legitimately runs for hours. Request headers must arrive within 10 seconds. A
request body may make the server wait at most 60 seconds in one read, and the waits summed over
the body may reach 2 minutes plus one second for every 1,024 bytes received; past either limit the
request fails, and an upload route answers `408 body-incomplete` (as it does a body whose
connection ended before it was whole). Time the server spends elsewhere (writing to disk, relaying to a slow visitor) is
not counted, so a body that keeps arriving at any usable rate never fails, and a cut upload resumes
like any dropped connection.

**Every response** carries `X-Content-Type-Options: nosniff`, the redirects between the two
origins and their refusals included.

**Ids and paths.** A share id is 10 base58 characters. A file's public **slug** is a UUIDv4,
minted when the server first learns the file and kept for the life of the entry. A relative path
(*relpath*) names a file inside a share: `/`-separated, clean, relative, with no `.` or `..`
segment, no NUL or backslash, at most 4,096 bytes with segments of at most 255; anything else is a
`400`. Every relpath a request names is normalized to Unicode NFC on arrival, so the composed and
decomposed spellings of `café` are one path on every route. A path that addresses the server's own disk (a linked share's
source) is the exception and is matched byte for byte.

## Versions and the client header

The server's version (`GET /api/health` → `version`, `MAJOR.MINOR.PATCH`) is the version of the
wire contract. A minor version adds routes and fields; a patch never changes the wire.

**The window.** A client of contract `M.N` works with servers of major `M` whose minor is `N-1`,
`N` or `N+1`. Inside the window:

- a server of contract `M.N` keeps every request and response of an `M.(N-1)` client working;
- a new response field is *omitted when empty*, and its absence means "off";
- a client sends a new field, or calls a new route, only when the server's version says it has
  it. The server refuses an unknown field (see [§ Conventions](#conventions)), so a client that
  skipped that check gets a `400`, never a silently ignored field.

**`X-HyperDrop-Client: <version> <platform>`.** An authenticated request may name the client that
sends it, for example `X-HyperDrop-Client: 1.0.0 linux`: a version of 1-4, 1-5 and 1-6 digits and
a platform of 1 to 16 lowercase letters and digits. A value off that shape is ignored. The server
records it on the calling token (shown as `clientVersion`/`clientPlatform` in
`GET /api/me/tokens` and as `latestClient` on accounts) and judges it against its own window
before it reads the token:

- a client too old for this server → `409 client-outdated`;
- a client too new for this server → `409 server-outdated`.

The sentence names both versions and links the help page. A request with no header, or one off
the shape, is not judged. The routes that repair a mismatch are never judged:
`POST /api/server/update`, `GET /api/me`, `GET /api/me/totp`, `POST /api/me/totp` and
`POST /api/me/totp/confirm`. The unauthenticated routes (`GET /api/health`, sign-in, invites,
device links) are not judged either.

A client should also check the window itself, from `GET /api/health`, before it sends a
credential, and should refuse a server whose `serverID` differs from the one it saw first behind
the same address (see `GET /api/health` in [§ Server administration](#server-administration)).

## Authentication

Every account has one of two **roles**, `admin` or `user`. The first administrator is created on
first boot from `HYPERDROP_ADMIN_USER` and the admin password seed
([`docs/configuration.md`](configuration.md#environment-variables)); every other account is created
by an administrator. There is no account with special powers by its name.

**Tokens.** A client signs in once and keeps the **device token** it is given:
`hd_u_` followed by 64 hex characters (256 random bits). The server stores only its SHA-256, so the
token appears exactly once, in the response that minted it. Send it as
`Authorization: Bearer <token>` on every `/api/` call. Tokens do not expire; one is ended by
signing out, by revoking it from another device, by a password change that signs other devices
out, or by an administrator resetting the account's password or deleting it. An account holds at
most 200 tokens: minting one more removes the least recently used. A token's optional `label`
(at most 128 bytes) names the device in the account's token list.

An authenticated route answers:

- `401` `{"error":"invalid or missing token"}` (no code) for a missing, unknown or revoked token;
- `403 account-disabled` when the account is suspended or past its expiry;
- `403` `{"error":"admin only"}` (no code) on an admin route for a `user`;
- `409 client-outdated` / `server-outdated` as described above, before any of these.

**Usernames** are 3 to 32 characters of `a-z 0-9 . _ -` (`400 bad-name` otherwise). **A chosen
password** is 8 to 72 bytes (`400 password-too-short` / `password-too-long`). One of the 10,000 most common passwords is refused with `400 {"error":"this password is too common, choose another"}` (no `code`). The check applies only where a person chooses a password (creating an account, an administrator setting one, `PATCH /api/me/password`, the Synology rescue page), never to a generated password, a sign-in, a share password or the first administrator's password at install. A password already
set is never measured. Passwords are stored as bcrypt hashes (cost 10). A generated password is 16
base58 characters.

### Signing in

| Call | Behaviour |
|---|---|
| `POST /api/auth/login` `{"username","password","label","totp"}` | No auth. → `200 {"token","user":<account>}`. `username` and `password` are required (`400` otherwise, no code). A wrong username and a wrong password answer the same `401 bad-credentials`, and an unknown username costs a bcrypt compare like a known one. A suspended or expired account → `403 account-disabled`, answered only after a correct password. An account with a confirmed second factor and no `totp` → `401 totp-required`; a wrong, replayed or unknown code → `401 totp-invalid`. `totp` takes an authenticator code or a recovery code. Lockouts, an account's lane and the busy answer: [§ Lockouts and rate limits](#lockouts-and-rate-limits). |
| `POST /api/auth/invite` `{"token","label"}` | No auth. Spends a one-time **invite** for a device token, answered exactly as login. An invite (`hd_i_` and 64 hex, stored as its SHA-256) is minted with every account an administrator creates and with every password an administrator sets, lives 7 days, and is cleared by any password change and by turning a second factor on, and survives a sign-in with the password; an account holds one at a time. Unknown, spent or expired → `404 invite-invalid` (one answer for all three); an account with a confirmed second factor → `403 invite-needs-code`, and the invite is not spent; a suspended account → `403 account-disabled`. `token` missing → `400` (no code). |
| `DELETE /api/auth/token` | Signs the calling token out → `204` (also when it is already gone). Its push registration goes with it. So do, transitively, every computer it [signed in by phone](#signing-a-computer-in-with-a-phone) and every web session it approved, as at [`DELETE /api/me/tokens/{id}`](#your-account) for the caller itself; the phones it signed in through a device link stay signed in. |

### Web sessions

The web client never holds a device token. It signs in to a **web session**, carried only in the
cookie `__Host-hd_web` (`HttpOnly; Secure; SameSite=Strict; Path=/`, no `Domain`, so it never
reaches `files.<domain>`). A session's value is `hd_w_` followed by 64 hex characters; the server
stores a domain-separated hash of it (SHA-256 of `hyperdrop-web-session` and a newline before the
value), so it never works as a bearer token. A session is a row of the account's token list,
labelled `Web browser · <browser> on <system>`, revocable there and ended by a password change
like any device. A **public** session (the default) is a browser-session cookie that ends 30
minutes after its last use or 12 hours after sign-in, whichever comes first; a **kept** one
(`keep`, "this is my computer") lives 30 days after its last use, its cookie with
`Max-Age=2592000`. A request marked `X-HyperDrop-Background: 1` does not count as a use. A use
moves a session's deadlines at most once a minute; when it moves a kept one's, the answer sets the
cookie again with a fresh `Max-Age=2592000`. Every `Set-Cookie` of the session cookie, a clear
(`Max-Age=0`) included, carries all of `HttpOnly; Secure; SameSite=Strict; Path=/`: a browser
ignores a clear of a `__Host-` cookie without `Secure`.

A request **without** an `Authorization` header is judged by the cookie only when it arrived on the
app host (any host when the server has no domain), carries `X-HyperDrop-Client: <contract> web`,
its `Origin`, when present, is the app origin, and its `Sec-Fetch-Site`, when present, is
`same-origin`; otherwise it is `401` like a missing token. A request with an `Authorization` header
is judged by its bearer token alone.

A web session takes only the routes that answer JSON a browser may hold. A route that answers file
bytes or other non-JSON content on the app origin (`GET /api/sources/file`, the owner's poster and
tile reads, `GET /api/admin/log`), and a route that mints or answers a bearer token or exists for
installed apps alone (the device links, a phone's claim, approval and denial of a browser's
sign-in, push registration, console activity, `DELETE
/api/auth/token`, `POST /api/server/update`, `PUT /api/server/web`, the Live Share routes, `GET /api/local-addresses`),
answers a web session `401 web-session-refused` before the session is looked up, so the refusal
does not count as a use. Every answer to a web session carries `Cache-Control: no-store`. An admin
**write** (any method but `GET` and `HEAD` on an admin route) from a web session needs the session
elevated (`POST /api/web/session/elevate`, below): `403 web-elevation-required` otherwise, a code
of its own, distinct from a route's [step-up](#step-up) (`step-up-required`). A route that asks for
`currentPassword` still asks for it, and checks it, but on **admin routes** an elevated session is
not asked for the second-factor code (the elevation proved it within the last 10 minutes), so one
admin change from the web needs one code. An admin route aimed at the caller's own account
(`PATCH /api/users/{name}` with the caller's own name) and every other route's step-up (changing
your own password, turning your second factor off, new recovery codes) ask for the code from every
caller, elevated or not. The elevation itself always asks for the code. An admin read needs no
elevation, and a device token never does. A `DELETE /api/me/tokens/{id}` that signs the calling
web session out, its own row or the device that approved it, also clears its cookie. A password change made from a web session answers no
token: see `PATCH /api/me/password`. A web session's `PATCH /api/users/{name}` naming its own
account with `password` or `resetPassword` → `403 use-change-password`, and nothing changes: the
own password changes through `PATCH /api/me/password`. A bearer caller is not refused.

| Call | Behaviour |
|---|---|
| `POST /api/web/session` `{"username","password","totp","keep"}` | No auth; the request must meet the cookie's conditions above (`403 web-session-refused` otherwise). → `200 {"user":<account>,"session":{"keep","expiresAt","idleSeconds"}}` and the cookie, `Cache-Control: no-store`; never a token. Answers and lockouts are login's, including the account's lane, shared with login; a browser holding a valid `__Host-hd_known` cookie (set by a sign-in with `keep:true`, read by this route alone) is counted on a lane of its own instead: [§ Lockouts and rate limits](#lockouts-and-rate-limits). The web client turned off → `403 web-off`; not served ([§ The web client](#the-web-client)) → `503 web-unavailable`. |
| `GET /api/web/session` | Web session only (`400 web-session-only` for a bearer). → `200 {"user","session":{"keep","expiresAt","idleUntil","elevatedUntil"}}`, `elevatedUntil` only while elevated. No bundle served → `503 web-unavailable`. |
| `DELETE /api/web/session` | Web session only (`400 web-session-only` for a bearer); the request must meet the cookie's conditions above (`401` otherwise). Deletes the session the cookie names, if any, clears the cookie and clears every share access cookie (`hd_<share id>`) the request carries, with the attributes its unlock set (the page origin's copies). With a domain it answers `200` `{"accessClear":"https://files.<domain>/access/clear?t=<token>"}`, composed from the server's own origins, and sets the one-minute `hd_clear` cookie (`Domain=<domain>`, `Path=/access/clear`) holding the token's nonce; the web client loads exactly that address as a picture, which clears the files origin's copies. Without a domain, `204` and no `accessClear`. Either answer comes whatever the cookie names (a session signed out, expired or revoked, none at all) and whether or not the web client is served. Never judged against the version window. |
| `POST /api/web/session/elevate` `{"currentPassword","totp"}` | Web session only. A [step-up](#step-up) (`totp` on an account with a second factor) → `200 {"elevatedUntil"}`, 10 minutes from now. No bundle served → `503 web-unavailable`. |

### Signing in a phone from a signed-in device

A signed-in device can let a second device (typically a phone) sign in to the same account
without typing the password on it. The signed-in device mints a short-lived **device link** and
shows its secret (as a QR code, say); the phone claims it, shows a two-digit number, and the owner
types that number on the first device to approve.

| Call | Behaviour |
|---|---|
| `POST /api/me/device-links` `{"currentPassword"?,"totp"?}` | Mints a link for the calling token. No password is needed; the body may be `{}`. A body with `currentPassword` is checked as a [step-up](#step-up) and marks the link stepped up, so its approval takes the number alone. Refused `403 device-too-new` for a token younger than 24 hours, before anything else is read. → `201 {"id","secret","expiresAt","windowEndsAt"}`. The `secret` (32 random bytes, base64url) is answered once; the server keeps its hash. A link lives **30 s** unclaimed; `windowEndsAt` is 3 minutes after the mint, the last moment it can be renewed. Minting removes every other live link of the account. |
| `GET /api/me/device-links/{id}` | *Compressed.* The link's state, for the token that minted it: `{"state","expiresAt","label","platform","sameNetwork","address"}`. `state` is `minted`, `claimed`, `approved`, `spent`, `burned` or `expired`. Once a phone claimed it, `label` and `platform` are what the phone sent, and `sameNetwork` is `true` when it claimed from the minting device's address (an IPv6 address compared by its /64), and `address` is the address the phone claimed from, answered while the link is claimed or approved and kept in memory only (absent after a restart); each is omitted when empty. Another token's link → `404 device-link-invalid`. |
| `POST /api/me/device-links/{id}/renew` | A minted, unclaimed link gets a new `secret` and a new 30 s, never past `windowEndsAt` → `200`, the mint's shape. The old secret stops working. Anything else → `404 device-link-invalid`. |
| `POST /api/me/device-links/{id}/approve` `{"number","totp"}` | Approves a claimed link with the number the phone shows → `204`. A `number` outside 10-99 → `400` (no code), the link unchanged. A different number → `409 device-link-wrong-number`, and the link is **burned**. Then, on an account with a second factor, a link not stepped up needs its code in `totp`: missing → `401 totp-required`, wrong → `401 totp-invalid`, the link left claimed; wrong codes count as step-up guesses. Not claimed, or past its claim window → `404 device-link-invalid`. |
| `POST /api/me/device-links/{id}/deny` | Burns a link that is not yet spent → `204`; otherwise `404 device-link-invalid`. |
| `POST /api/auth/device-link/claim` `{"secret","label"}` | No auth. The phone presents the scanned secret. The first claim of a live link wins and starts a 5-minute window to finish → `202 {"claimId","pollSecret","number","approver","username"}`: `number` (10-99) is what the phone shows, `approver` the label of the device that minted the link. The phone's platform is read from its `X-HyperDrop-Client`. A second claim of a link already claimed or approved **burns** it. Unknown, expired, burned, spent or malformed → `404 device-link-invalid`. |
| `POST /api/auth/device-link/poll` `{"claimId","pollSecret"}` | No auth. → `202 {}` while the claim waits for approval (not counted on any lockout), then `200 {"token","user"}`, exactly as login, once approved. The token is minted in the transaction that marks the link spent, so a link yields at most one token. Anything else → `404 device-link-invalid`; a suspended account → `403 account-disabled`. |

Every `device-link-invalid` from the two unauthenticated routes counts on the sign-in lockout. The
row keeps only hashes of the secrets and an HMAC (under the volume secret) of each device's
address. Link rows are removed a day after their mint.

### Signing a browser in with a phone

The other way round: a browser that has no account to mint from (a public computer) signs in to
a web session with a phone already signed in to the account, without typing the password. The
browser asks for a **sign-in request** and shows its code as a QR code; the phone claims it with
its device token, the browser then shows a two-digit number, and the phone's owner types that
number on the phone, which approves (with the account's code when it has a second factor). The
browser's next poll sets the session cookie. Requests live in memory only: a restart forgets
every one, and so does turning the web client off.

The code is `hdweb1.` followed by unpadded base64url of `{"s":<the server's address>,"i":<its
serverID>,"w":<the request's secret>}`. A phone checks `s` and `i` against the server it is
signed in to before it sends the secret anywhere.

| Call | Behaviour |
|---|---|
| `POST /api/web/phone-sign-in` `{}` | No auth; the request must meet the cookie's conditions ([§ Web sessions](#web-sessions); `403 web-session-refused` otherwise) and the address must not be locked out. → `201 {"id","pollSecret","code","expiresAt"}`, `Cache-Control: no-store`: `code` the hdweb1 code above, `expiresAt` 2 minutes from now, when an unclaimed request lapses and the browser asks for a new one. An address key (an IPv6 address by its /64) holds at most 3 live requests, an IPv6 /48 at most 32 across its /64s, and an IPv6 /32 at most 128 across its /48s: past any → `429 locked-out`, `Retry-After` naming when the oldest of those lapses. A server holding 4,096 → `503` (no code) with `Retry-After`. The web client turned off → `403 web-off`; not served → `503 web-unavailable`. |
| `POST /api/web/phone-sign-in/poll` `{"id","pollSecret"}` | No auth; the same conditions and refusals as the request. → `202 {"state":"waiting"}` until a phone claims it, `202 {"state":"claimed","number","username"}` (the number to show, 10-99, and the account whose phone claimed it, which only the holder of `pollSecret` reads) until it is approved, then `200 {"user","session":{"keep","expiresAt","idleSeconds"}}` and the cookie, exactly as `POST /api/web/session` answers a public session: never kept, never a token. The session is labelled `Web browser · <browser> on <system>` from the `User-Agent` the request was made with, and records the approving device as `viaToken`. The poll that collects it spends the request, so a request yields at most one session. Unknown, lapsed, burned, denied or spent, a wrong `pollSecret`, or an approving device signed out since → `410 web-sign-in-expired`. The account suspended or expired since the approval → `403 account-disabled`, and the request is spent; an account deleted since takes the approving device with it, so → `410`. A poll is never counted on the lockout. |
| `POST /api/me/web-sign-ins/claim` `{"secret"}` | A device token (a web session is refused `401 web-session-refused`) signed in for 24 hours (`403 device-too-new` otherwise). The first claim of a waiting request draws its number and gives it 5 minutes from the claim to be approved and collected → `200 {"id","browser","address","sameNetwork"}`: `browser` the summary of the browser's `User-Agent` (`Chrome on Windows`), `address` the address it asked from, `sameNetwork` `true` when the phone claims from the browser's address key. A claim of a request already claimed **burns** it, and a claim burns every other request the account claimed, so an account approves one at a time. Unknown, lapsed or burned → `410 web-sign-in-expired`. |
| `POST /api/me/web-sign-ins/{id}/approve` `{"number","totp"}` | The token that claimed it. A `number` outside 10-99 → `400` (no code), the request unchanged. A different number → `409 device-link-wrong-number`, and the request is **burned**. Then an account with a second factor gives its code in `totp`: missing → `401 totp-required`, wrong → `401 totp-invalid`, the request left claimed; wrong codes count as step-up guesses. → `204`. Not claimed by this token, or past its 5 minutes → `410 web-sign-in-expired`. |
| `POST /api/me/web-sign-ins/{id}/deny` | The token that claimed it: burns the request → `204`; otherwise `410 web-sign-in-expired`. |

A device token a phone signed in ([below](#signing-a-computer-in-with-a-phone)) approves no
browser: its claim → `403 desktop-sign-in-refused`.

### Signing a computer in with a phone

A desktop app signs in to an account with a phone already signed in to it, the browser's flow
above with a device token at the end. The computer asks for a request **bound to the username
typed there** and shows its code as a QR code; a phone of that account claims it, the computer
shows a two-digit number, the phone's owner types it on the phone, and the computer's next poll
collects an ordinary device token. Requests live in memory only, in a book of their own: a
browser's request is never claimed, polled or approved here, nor the reverse. A restart forgets
every one, and so does turning the switch off.

The code is `hddesk1.` followed by the same payload as `hdweb1.`. All five routes need an
`X-HyperDrop-Client` header naming a version and a system, judged before anything else
(`400 client-required` without one), so every one of them is under the version window. The two
unauthenticated routes answer installed apps only: with an `Origin` or `Sec-Fetch-Site` header,
or the `web` system → `403 desktop-sign-in-refused`. Then the [version window](#versions-and-the-client-header), the
switch (`desktopSignIn` in [server settings](#updating-the-server), on unless turned off;
`403 desktop-sign-in-off` while off) and the sign-in lockout apply, in that order. Bodies are
decoded strictly. A device token that a phone signed in this way never approves any sign-in: not
a computer, a browser, or a phone through a device link (`403 desktop-sign-in-refused`). Signing
the approving device out, by anyone including itself, signs out every computer it signed in this
way (`DELETE /api/me/tokens/{id}`, [Your account](#your-account)).

| Call | Behaviour |
|---|---|
| `POST /api/auth/desktop-sign-in` `{"label","username"}` | No auth; the conditions above. → `201 {"id","pollSecret","code","expiresAt"}`, `Cache-Control: no-store`, `expiresAt` 2 minutes from now. `username` is the account's name as typed to sign in, matched with ASCII letters lowered; a name no account can have → `400 invalid`. Any other name gets the same answer whether or not an account has it, is suspended or is an administrator's. `label` is what the computer calls itself: control and format characters are removed, whitespace collapsed, and it is cut to 40 characters (`Computer` when nothing is left). An address key holds at most 3 live requests, an IPv6 /48 at most 32 and an IPv6 /32 at most 128: past any → `429 locked-out` with `Retry-After`. A server holding 4,096 → `503` (no code) with `Retry-After`. |
| `POST /api/auth/desktop-sign-in/poll` `{"id","pollSecret"}` | No auth; the same conditions. → `202 {"state":"waiting"}`, then `202 {"state":"claimed","number"}` (the number to show, 10-99), then once approved `200 {"token","user"}`, exactly as login answers. The token is labelled `Phone sign-in: <label>`, carries the request's system as its `clientPlatform`, and lists with `method:"phone"` and `approvedBy` in `GET /api/me/tokens`. The poll that collects it spends the request first, and the mint checks again: the approving device still signed in, not a web session and not itself signed in by phone, and the account active, else `410 desktop-sign-in-expired`; an administrator's account → `403 desktop-sign-in-admin`; the approving device past its daily limit → `429 desktop-sign-in-limit`; the account at its device limit → `409 too-many-devices` (no device is signed out to make room). Unknown, lapsed, burned, denied, spent or a wrong `pollSecret` → `410 desktop-sign-in-expired`. A poll is never counted on the lockout. |
| `POST /api/me/desktop-sign-ins/claim` `{"secret"}` | A device token (a web session is refused `401 web-session-refused`), not itself signed in by phone (`403 desktop-sign-in-refused`), signed in for 24 hours (`403 device-too-new`), with the switch on (`403 desktop-sign-in-off`), of an account that is not an administrator's (`403 desktop-sign-in-admin`), which signed in fewer than 3 computers in the last 24 hours (`429 desktop-sign-in-limit`). The first claim of a waiting request draws its number and gives it 5 minutes → `200 {"id","label","platform","address","sameNetwork"}`: what the computer calls itself and its system (its own claims), the address it asked from, and whether the phone claims from the computer's address key. Another account's claim → `410 desktop-sign-in-expired` and leaves the request untouched. A second claim by the right account burns it, and a claim burns every other computer request the account claimed. Unknown, lapsed or burned → `410 desktop-sign-in-expired`. |
| `POST /api/me/desktop-sign-ins/{id}/approve` `{"number","totp"}` | As the browser's approve: a different number → `409 device-link-wrong-number` and the request is burned; an account with a second factor gives its code (`401 totp-required`, `401 totp-invalid`, the request left claimed). → `204`. Otherwise `410 desktop-sign-in-expired`. |
| `POST /api/me/desktop-sign-ins/{id}/deny` `{}` | The token that claimed it: burns the request → `204`; otherwise `410 desktop-sign-in-expired`. |

### Two-factor authentication

An account may add a TOTP second factor (RFC 6238: SHA-1, 6 digits, 30-second steps, a 20-byte
secret). It is opt-in per account. A code is accepted one step either side of now, and never twice:
the newest accepted step is stored and a code at or below it is refused even when it is correct.
Verification and its spend happen in the same transaction as what it authorizes. Recovery codes
are 10 codes of 10 characters over `ABCDEFGHJKLMNPQRSTUVWXYZ23456789`, shown `XXXXX-XXXXX`; spaces,
dashes and case are ignored, and each is stored as a SHA-256 and works once. The TOTP secret is
stored sealed under the volume secret (see [`docs/security.md`](security.md#sealed-values)).

The factor is asked at sign-in and in every [step-up](#step-up). It also blocks signing in with an
invite (`403 invite-needs-code`).

| Call | Behaviour |
|---|---|
| `GET /api/me/totp` | *Compressed.* `{"enabled","pending","recoveryCodesLeft","confirmedAt"}` (`confirmedAt` omitted while off). `pending` means an enrolment was started and not confirmed; it reads as off everywhere. The secret is never answered here. |
| `POST /api/me/totp` `{"currentPassword"}` | Starts an enrolment → `200 {"secret","uri","issuer","account"}`, `uri` being the `otpauth://` URL a QR code carries. Needs the account's password (`403 step-up-required` without it, `401 wrong-password`). Enables nothing until confirmed; starting again replaces the pending secret. A confirmed factor → `409 totp-already-on`. |
| `POST /api/me/totp/confirm` `{"code"}` | Finishes the enrolment → `200 {"enabled":true,"recoveryCodes":[…10]}`, the only time the recovery codes are shown. No enrolment pending → `409 totp-not-pending`; a wrong or empty code → `401 totp-invalid`, counted on the step-up lockout. |
| `DELETE /api/me/totp` `{"currentPassword","code"}` | Turns the factor off → `200 {"enabled":false}`. Needs the password and a valid code. An account with no factor answers the same `200` without checking anything. |
| `POST /api/me/totp/recovery` `{"currentPassword","code"}` | A fresh set of recovery codes, every old one invalidated → `200 {"recoveryCodes":[…10]}`. No factor → `409 totp-off`. |
| `DELETE /api/users/{name}/totp` `{"currentPassword","totp"}` | Admin. Clears another account's factor → `200 {"username","enabled":false}`. Aimed at the caller → `403 totp-self-reset`: an administrator's own factor is turned off with its own password and code. Clearing another **admin's** factor needs the caller's step-up; a user's needs no body. Unknown account → `404 user-not-found`. |

An operator who lost their only factor clears it on the box with `hyperdrop-server reset2fa
<account>` ([`docs/configuration.md`](configuration.md#operator-subcommands)).

### Step-up

The calls that would let a stolen token take over an account or the server ask for the caller's
own password again, and a code when the caller has a second factor: changing one's password,
starting, turning off or re-keying the second factor, the admin-granting
account edits ([below](#accounts-admin)), `PUT /api/domain` with `adopt`, `PUT /api/connectivity`
and `POST /api/server/update`. The body carries `currentPassword` and `totp` (`code` on the
second-factor routes). The answers are the same everywhere:

- no `currentPassword` → `403 step-up-required` (the one answer a client asks for the password on);
- a wrong password → `401 wrong-password`;
- a missing code → `401 totp-required`; a wrong or replayed one → `401 totp-invalid`;
- locked out → `429 locked-out`.

### Lockouts and rate limits

Guessing is limited per **key**. An address key is the client's IP address, an IPv6 address
counting by its /64 (behind a listed proxy, the address the PROXY header names; see
`HYPERDROP_TRUSTED_PROXIES`). **10 wrong guesses within an hour block the key for 12 hours**
(a share password's address key blocks for 1 hour, doubling while it repeats, see
[Public routes](#the-routes));
every attempt while blocked, right or wrong, answers `429 locked-out` with `Retry-After` in
seconds. A key whose remaining guesses are all in flight answers the same `429` with
`Retry-After: 5`. A correct answer forgets only the guesses aimed at the same target (the same
account, or the same share). The counters live in memory and a restart clears them.

| What is guessed | Keys counted |
|---|---|
| A password at sign-in; an invite; a device-link secret or poll | the address |
| A phone sign-in request or its poll | nothing is counted (both secrets are 32 random bytes), but a locked-out address is refused, an address holds at most 3 live requests and an IPv6 /48 at most 32 |
| A password or a second-factor code at sign-in or at the web sign-in | the account's **lane**, read by `POST /api/auth/login` and `POST /api/web/session` alike; a web sign-in from a browser holding a valid `__Host-hd_known` cookie counts on that browser's lane instead |
| A second-factor code at sign-in | the address and the account |
| A step-up password or code; an enrolment's confirm code; a device-link approval's code | the address and the calling token |
| A share's password (`POST /unlock/{id}`, `?pw=`) | the address at that share, on a separate counter, for a first-party guess only (see [Public routes](#the-routes)), and the share's lane |
| A password or code at the web sign-in | the address and the code's account key as at sign-in, and the account's lane (or the kept browser's); a wait on the account's keys or lane says "for this account", one on the address "from your address" |

**Lanes slow guessing from many addresses and never block.** A lane counts every failed sign-in on
it, a wrong password or a wrong second-factor code after the right password. After ten, it admits
one attempt per 30 seconds and answers every other attempt `429 locked-out` with `Retry-After` of
30 at most, before any password is compared; an hour without a failure resets it. There is a lane
per account name (case-folded, shared by the apps' sign-in and the web sign-in, and a name no account
has is counted alike), a lane per kept browser, and a lane per share. A success on an account's or
a share's lane keeps its count, because its failures are other people's guesses; a success on a
kept browser's lane resets it. A sign-in that checks no wrong password (one answered
`totp-required` because the code is missing, or one that never reached the compare) gives back the
slot it took, so an account with a second factor signs in with one slot, not two. An
administrator's password reset and the account's own password
change free the account's lane. Lanes live in a map of their own bounded at 65,536 entries, where
a new key replaces an entry with no attempt in flight, preferring the unthrottled one with the
fewest failures, so a flood of made-up names evicts unthrottled names first: only when every
sampled entry is throttled does one go, the one whose quiet hour ends soonest, and an entry with
an attempt in flight never goes. Each refusal's `Retry-After` is 30 seconds at most, but while
someone keeps guessing, a new browser or app signing in with a password alone may wait as long as
that lasts; a kept browser, phone sign-in, a linked device and an administrator's password reset
are not affected. A kept browser is one where a web sign-in chose "This is my
computer": it holds the `__Host-hd_known` cookie, which a sign-out leaves valid and a password
change or an administrator's reset of the password voids (see
[`security.md`](security.md#guessing-and-rate-limits)). Phone sign-in for the web and for computers
reads no lane, so an owner can always sign in with a phone already signed in.

Sign-in and step-up share the address counter, so ten wrong step-ups from one address also lock
that address out of sign-in.

At most 2 password checks run at once; with more than 32 waiting, sign-in and step-up answer
`503` (no code) with `Retry-After: 2`. Share-password checks have their own 2 slots, at most 1 per
share owner, so one account's popular links cannot hold every slot.

**Share creation** is rate-limited per non-admin account: a bucket of 30 that refills at 300 an
hour; past it, `429 rate-limited` with `Retry-After`. Starting a new live share draws on the same
bucket. Uploads are not rate-limited: an account's quota bounds the bytes.

## Your account

| Call | Behaviour |
|---|---|
| `GET /api/me` | *Compressed.* The calling account (below). Never judged against the version window. |
| `GET /api/me/tokens` | *Compressed.* `{"tokens":[{"id","label","createdAt","lastUsedAt","current","clientVersion","clientPlatform","viaToken","method","approvedBy","kind"}]}`, oldest first. Ids and labels only, never a token. `current` marks the calling token; `lastUsedAt` moves at most hourly; `clientVersion`/`clientPlatform` are what that token's `X-HyperDrop-Client` last named; `viaToken` is the id of the token that approved this one through a device link; `method` is `phone` for a computer a phone [signed in](#signing-a-computer-in-with-a-phone), and `approvedBy` the approving device's label at the approval, kept after that device goes; `kind` is `web` for a browser's [web session](#web-sessions), a device token carrying none. Each is omitted when empty. |
| `DELETE /api/me/tokens/{id}` `?alsoLinked=<id>,<id>` | Signs one device of the account out → `204`, together with what it signed in, in one transaction. Following `viaToken` from the revoked token, transitively, every computer [signed in by phone](#signing-a-computer-in-with-a-phone) (`method:"phone"`) and every web session goes with it, even when a device signs itself out. A phone it [signed in](#signing-in-a-phone-from-a-signed-in-device) through a device link goes only when its id is listed in the optional `alsoLinked` (comma-separated ids, empty items ignored, read up to the account's device limit of items), and what that phone signed in is followed only then; a listed id the cascade does not reach is ignored, and `alsoLinked` is ignored when the caller revokes itself. Revoking the calling token is a sign-out. Another account's id → `404 not-found`. Revoking **another** token from a token younger than 24 hours → `403 device-too-new`, so a token stolen minutes ago cannot sign the owner's other devices out. |
| `PATCH /api/me/password` `{"password","currentPassword","totp","signOutOthers"}` | Changes the caller's password. Step-up required. The new password's length is checked before the step-up, so a refused one spends no code. `signOutOthers` absent or `true`: every token of the account is revoked, the calling one included, and the answer is `{"token","signedOutOthers":true}`, a fresh token for the calling device to store in place of its old one; it keeps the old token's label and age. From a [web session](#web-sessions) the answer is `{"signedOutOthers":true}` with no token, and the browser gets a new session of the same kind, label and sign-in time in a new cookie. `false`: every token survives and the answer is `{"signedOutOthers":false}`, with no token. Any password change clears a pending invite. |
| `GET /api/local-addresses` | `{"addresses":["192.168.1.20:443",…]}`: the server's private, non-loopback IPv4 interface addresses joined with its HTTPS port, so a client on the same network can upload over the LAN. A client should treat each as a hint and use it only after a TLS handshake for the server's public name succeeds against it. Any signed-in account; `null` on a server with no domain or no such address. Not on the unauthenticated health route, so the LAN layout is not disclosed to strangers. |

Push registration (`GET`/`PUT`/`DELETE /api/me/push`) and `PUT /api/me/activity` are described in
[§ Push notifications](#push-notifications).

**The account object**, as `GET /api/me`, the users list and sign-in answer it:

| Field | Meaning |
|---|---|
| `username`, `role` | `role` is `admin` or `user`. |
| `createdAt` | When the account was created. |
| `usedBytes`, `shareCount` | What the account's shares hold now (stored bytes; a linked share's bytes are not counted). |
| `quotaBytes` | The account's storage quota; omitted when unlimited. |
| `disabled` | `true` while an administrator has suspended the account. |
| `accountExpiresAt` | When the account stops working; omitted when it never does. |
| `noEmbed` | `true` when the account's files refuse to be embedded by other sites (see [§ Public routes](#the-access-gate)). |
| `sourceRoots` | The server folders the account may create linked shares from (see [§ Linked shares](#linked-shares)); omitted when none. |
| `twoFactorEnabled` | `true` when a second factor is confirmed. |
| `latestClient` | `{"version","platform","lastUsedAt"}`: the newest client version any of the account's tokens reported; omitted when none has. |

## Accounts (admin)

Every route here is admin-only. Shares are never managed through these routes except by deleting
an account: an administrator's `/api/shares` is their own, like everyone's.

| Call | Behaviour |
|---|---|
| `GET /api/users` | *Compressed.* `{"users":[<account>…]}`, sorted by username. |
| `POST /api/users` | Creates an account. Body: `username`, `password`, `role`, `quotaBytes`, `noEmbed`, `disabled`, `accountExpiresAt`, `sourceRoots`, `currentPassword`, `totp` (also accepted: `clearAccountExpiry`, `confirmRevoke`, which change nothing on a new account). → `201 {"user","password","inviteToken"}`. `role` is `admin` or `user` (absent: `user`; anything else `400 bad-role`). An empty `password` makes the server generate one, answered once as `password`; a chosen one is never echoed. `inviteToken` is the account's one-time invite (see `POST /api/auth/invite`). **`quotaBytes` is required for a `user`** (`400 quota-required`; send `0` for no limit deliberately); a negative quota is a `400`. `sourceRoots` is validated like a linked share's source (`400 bad-source`). Creating an `admin` needs the caller's step-up. Then `400 bad-name` or `409 user-exists`. |
| `GET /api/users/{name}` | The account object itself (not wrapped). Unknown → `404 user-not-found`, as on every `/api/users/{name}` route. |
| `PATCH /api/users/{name}` | Edits any subset of the fields above; absent fields are unchanged. `clearAccountExpiry:true` removes the expiry; `disabled` suspends and resumes. `"resetPassword":true` sets a generated password, answered once; a non-empty `"password"` sets that one (both together → `400`). Either signs out every device of the account and mints a fresh invite. `sourceRoots`: absent unchanged, `[]` cleared, a list replaces. → `200 {"user","password","inviteToken"}` (the last two only when a password was set). |
| `DELETE /api/users/{name}` | Deletes the account **and every share it owns**, bytes included, and ends its running live shares → `204`. A share that survives the pass → `409 user-has-shares`. |

Rules on those edits:

- **An administrator cannot lock themselves out.** Demoting, suspending or setting an expiry on
  one's own account, and deleting it, → `403 self-target`. Clearing one's own expiry and editing
  the other fields stay allowed.
- **The server keeps an administrator.** An edit or delete that would leave no active
  administrator, or no administrator whose access never expires, → `409 last-admin`, checked
  before anything is removed.
- **Granting an admin identity takes the caller's step-up:** creating an admin, promoting an
  account, setting or resetting the password of an admin (one's own included) and clearing another
  admin's second factor. A bearer token alone must not be able to mint an administrator whose
  password its holder chose, because an administrator can update the server's binary.
- **Narrowing what an account may share revokes its linked shares.** A `PATCH` whose
  `sourceRoots` or `role` would leave the account's existing linked sources uncovered →
  `409 revokes-shares` with `"shares":[{"id","name","source","files"}]`, and nothing changes;
  send it again with `"confirmRevoke":true` to apply it. The revoke is written onto each share in
  the same transaction; a later edit that covers the source again restores it, links unchanged.
  This `409` is answered before the step-up is checked, so the code is not spent. Only an edit
  carrying `sourceRoots` or `role` decides revokes.

**What an account's limits do:**

- **Quota** (`quotaBytes`): committed bytes, plus the bytes of uploads in flight, plus the new
  upload must fit; checked before staging and again when a file commits. Refusal: `507 quota`.
- **Suspension and expiry**: the account's sign-in and tokens answer `403 account-disabled`, and
  every public link of its shares answers `404`. Content stays on disk; resuming restores the
  links.
- **`noEmbed`**: see [§ The access gate](#the-access-gate).
- A `507 no-space` refusing a share's `reserveBytes` names real disk figures only to an
  administrator; a `user` gets a generic sentence, since a user can trigger it at will.

## Shares

A **share** is a set of files behind one link. Every `/api/shares…` route is owner-scoped for
every role, an administrator included: an account sees and changes only its own shares, and
another account's share id answers `404 not-found`, indistinguishable from one that does not
exist. No share view names its owner.

A share's links are composed by the client from the server's domain:

- **View**: `https://<domain>/share/{id}`, minted once and never changed. What it opens is decided
  by the server each time it is visited ([§ What the View link opens](#what-the-view-link-opens)).
- **Download**: `https://<domain>/download/{id}/{slug}` for a share of one file;
  `https://<domain>/zip/{id}` for several, or `/zip/{id}?dir=<relpath>` for one folder of it.

A payload link naming `<domain>` costs its recipient one `308` to `files.<domain>`; that redirect
is part of the contract, so either spelling may be handed out.

### The share view

Every route that answers a share (create, read, list, the change feed, edits, file and folder
changes) answers this object:

```json
{
  "id": "4Gt8sQx2Lm", "name": "Holiday", "folder": true,
  "createdAt": "2026-07-14T12:00:00Z", "modifiedAt": "2026-07-14T12:05:00Z",
  "expiresAt": "2026-07-21T12:00:00Z", "hasPassword": true, "hasPoster": true,
  "pending": [{"kind": "password", "applyAt": "2026-07-15T00:00:00Z", "clear": true}],
  "files": [
    {"path": "a.jpg", "size": 123, "slug": "7c1e…", "sha256": "…", "viewable": true,
     "addedAt": "2026-07-14T12:00:03Z", "committedAt": "2026-07-14T12:00:03Z"},
    {"path": "clip.mp4", "size": 456, "slug": "9a0b…", "viewable": true, "pending": true}
  ],
  "folders": ["empty folder"],
  "fileCount": 2, "totalSize": 579, "visitors": 12
}
```

Always present: `id`, `name` (`""` for a share created without one), `createdAt`, `files` (an
array, never `null`), `fileCount`, `totalSize`, `visitors`. Every other field is *omitted when
empty*:

| Field | Meaning |
|---|---|
| `folder` | Display hint: the share was made from a folder. |
| `modifiedAt` | The last change to the share's files or properties (scheduled changes count when queued, cancelled or applied). Absent until the first change. Visits, pins, read marks, upload progress and previews do not move it. |
| `expiresAt` | When the share's links stop answering. |
| `hasPassword` | The share has a password. The hash never leaves the server. |
| `password` | The password itself: only on `GET /api/shares/{id}`, only for the owner, and only when the server holds a readable copy (see [below](#reading-one-share)). |
| `hasPoster` | A preview frame is stored (`GET /api/shares/{id}/poster`). |
| `entry`, `media`, `listing` | What the View link opens ([below](#what-the-view-link-opens)). |
| `text` | A text share ([below](#text-shares)). |
| `pinnedAt` | When the owner pinned the share; clients list pinned shares first, the newest pin on top. The server's own order ignores it. |
| `pending` | Scheduled changes: `{"kind":"password"|"expiry","applyAt","clear"}`, `clear:true` meaning the field will be removed. The values stay on the server. |
| `folders` | The share's explicit folder records (an empty folder is one); folders that a file's path implies are read off `files`. At most 1,000. |
| `filesTruncated` | `files` is a window onto the share (in a listing or the change feed); `fileCount` and `totalSize` still describe the whole share. |
| `receive`, `note`, `closed`, `maxBytes`, `maxFiles`, `notify`, `seenAt`, `incoming` | A Receive Inbox ([§ Receive Inboxes](#receive-inboxes)). |
| `source`, `sources`, `sourceMissing`, `linked` | A linked share ([§ Linked shares](#linked-shares)). |

`visitors` counts the distinct visitors who read the share ([§ Who visited](#who-visited)).
`totalSize` sums every file the share lists; on a truncated row it is the committed bytes plus the
linked bytes, without the declared sizes of pending files.

**A file**:

| Field | Meaning |
|---|---|
| `path` | The relpath inside the share, as the owner named it. |
| `size` | Bytes. For a pending file, the declared size. |
| `slug` | The file's public URL token (UUIDv4). Links carry the slug, never the file name. |
| `sha256` | Hex SHA-256 of the committed bytes. Absent on pending and linked entries. |
| `viewable` | Whether a browser renders the file inline: `image/*`, `video/*`, `audio/*`, `text/*`, `application/pdf`, `application/json`, `application/xml` and any `+xml` or `+json` type. Decided by the server from the type it resolved at commit (by extension, then by sniffing the first 512 bytes), so every client agrees. An extension that maps to an XML or JSON type counts only when the first 512 bytes are text (UTF-8 with no NUL byte, or UTF-16 after a byte order mark); binary content under such a name (a macOS `.pkg`, which some mime tables map to an `+xml` type) resolves to `application/octet-stream`. A linked entry's type comes from its name, and `/view` applies the same check to its bytes before serving it inline. It decides the disposition `/view` serves with, never whether a share has a View link. |
| `addedAt` | When the path first committed in this share (kept across replacements). |
| `committedAt` | When its current bytes committed; a replacement under the same slug moves it. For a linked entry, the file's modification time. |
| `pending` | Declared in the creation manifest, bytes not uploaded yet (not to be confused with the share's `pending` list). |
| `linked` | The entry comes from a linked source's walk: no upload, no quota, no delete. |
| `uploadedBy` | Inboxes only: groups the files one sender sent. |
| `hasThumb` | On the owner's view of a gallery: a gallery tile exists for this file and is not older than it. |

### Creating a share

`POST /api/shares` → `201` with the share view. Every field is optional; the body is at most
4 MiB (`413 body-too-large`).

| Field | Meaning |
|---|---|
| `name` | The title on the share's pages and the zip's file name. Trimmed; at most 120 characters, no `/`, no control character (`400` otherwise). Required for an inbox. |
| `folder` | Display hint. |
| `password` | Non-empty: every public route of the share asks for it. At most 72 bytes (what bcrypt reads; more is `400 password-too-long` on every route that sets a share password), with no minimum. Stored as a bcrypt hash, plus a sealed copy the owner can read back. |
| `expiresInSeconds` | Positive: the share expires that long from now (capped at a century). Zero, negative or absent: never. |
| `reserveBytes` | The total the client is about to upload. Checked against the owner's quota (`507 quota`) and then against free disk, so two uploads cannot both start into room for one (`507 no-space`); a refused share is not created. What is reserved is clamped to the account's half of the usable space, less what the account already holds, and is never refused for that. Each write into the share draws on the reservation when it is admitted; what the reservation cannot cover is admitted window by window like any other write. A reservation lives 15 minutes, restarted each time the share's uploads land 64 MiB of new bytes (a re-sent range counts nothing); one past that is released, and the upload goes on with each write admitted on its own. |
| `files` | `[{"path","size"}]`, the files the share will hold, at most 10,000 (`413 manifest-too-big`). Each becomes a pending entry with its slug minted now, so every link works before a byte is sent ([§ Early links](#early-links)). Each path is validated like an upload's and must be unique; sizes must not be negative (`400` otherwise, and nothing is created). A share that needs no per-file link before upload can skip it. |
| `entry`, `media`, `listing` | What the View link opens ([below](#what-the-view-link-opens)). |
| `text` | A text share ([below](#text-shares)). |
| `receive`, `note`, `maxBytes`, `maxFiles` | A Receive Inbox ([§ Receive Inboxes](#receive-inboxes)); `note` and the caps on any other share → `400`. |
| `source`, `sources` | A linked share ([§ Linked shares](#linked-shares)). |

A share created with no file and no upload activity is deleted by the housekeeping pass after an
hour (an inbox, a linked share and a share with a folder record excepted), so create one when you
are about to upload into it. Creating counts on the share-creation rate limit
([§ Lockouts and rate limits](#lockouts-and-rate-limits)).

### Listing shares

`GET /api/shares?limit=&after=&offset=&q=&kind=` → *compressed*
`{"shares":[<share>…],"total","offset","totalBytes","nextCursor"}`, newest first.

- `limit`: default 500, at most 2,000 (an invalid value is the default).
- `after`: page by handing back the previous page's `nextCursor`; the next page resumes after its
  last row, so a share created or deleted between pages neither repeats nor skips a row.
  `nextCursor` is present whenever a page is full. An unparseable cursor → `400`. `offset` still
  works, costs a skip per row, and is ignored when `after` is given.
- `q`: a case-insensitive substring filter on names; `total` then counts the matches.
- `kind`: absent lists ordinary shares only; `receive` lists Receive Inboxes only; anything else
  → `400`. `total` and `totalBytes` (committed bytes) cover the rows the filters select.
- **A page is bounded in files.** Each row carries at most 100 file entries (`filesTruncated`),
  and once 50,000 entries have accumulated on a page, later rows carry none. Re-read one share with
  `GET /api/shares/{id}` for every path.

### Reading one share

`GET /api/shares/{id}` → *compressed* share view, never windowed: this is how a client recovers the
paths a listing truncated. For the owner it adds `password` when the share has one and the server
holds a readable copy, with `Cache-Control: no-store`. The password is kept as a copy sealed under
the volume secret beside its bcrypt hash ([`docs/security.md`](security.md#sealed-values)); a copy
that no longer opens (the volume moved without its secret, or a different server version changed
the password) is left out while `hasPassword` stays true. The password never appears in a
listing, the change feed, an edit's answer or any public route.

### Watching for changes

| Call | Behaviour |
|---|---|
| `GET /api/shares/watch?since=<cursor>&progress=<cursor>` | Long poll. Without `since` → at once `{"cursor","changed":false,"progress"}`, with `uploads` while any of the account's inboxes has an upload in flight (upload progress, below). With `since` → as soon as any of the account's shares changed past it `{"cursor","changed":true}`, otherwise after 50 seconds `{"cursor","changed":false}`. An unparseable or stale cursor answers `changed:true` at once. Loop with the returned cursor; re-read the list (or the change feed) on `changed`. At most 16 parked requests per account and 256 per server: past either, `429 too-many-watchers` with `Retry-After: 5`, and a client should fall back to polling. |
| `GET /api/shares/changes?since=<cursor>&limit=N` | *Compressed.* The changes themselves: `{"changes":[{"share":<share>}|{"deleted":"<id>"}…],"cursor","more"}`, one entry per changed share, newest state only, rows windowed at 100 files. `limit` default 500, at most 2,000; `more:true` means call again with the returned cursor, which never skips an entry that did not fit. A missing, unparseable, pruned (the journal keeps 30 days) or unknown cursor → `{"reset":true,"cursor"}`: re-read the whole list, then follow from that cursor. |

The cursor is opaque: compare it for equality only. The two routes share it, and it survives a
restart. It is the server-wide sequence of the change journal, so it advances on any account's
change: it shows how often the server's shares change, never what changed, whose, or which.
Inbox rows in the change feed carry `incoming` as it stood when the answer was built.

**Upload progress rides the watch.** A watch that sends `progress=<cursor>` (the `progress` the
last answer carried; a call without `since` always follows it) is also answered when the uploads
into the caller's OWN inboxes move, with `changed:false` and the journal cursor unchanged. Every
such answer carries `progress`, the cursor to send next, opaque like `cursor`. When it differs
from the one sent, the answer carries
`"uploads":[{"share":"<id>","incoming":[{"name","bytes","total","by"}]}]`: EVERY inbox of the
caller's with an upload in flight, each `incoming` in the inbox row's shape, so an inbox it does
not name has none (and the field is absent when none has). The progress cursor moves when a
name is claimed, when an upload ends, and while bytes arrive at most once a second per inbox.
None of it is written to the database or the journal. A progress cursor this server process did
not issue (one from before a restart, or an unparseable one) is answered at once. A call with a
`since` and no `progress` waits for the journal alone.

### Editing a share

`PATCH /api/shares/{id}` → `200` with the share view. Absent fields are unchanged; the body is at
most 1 MiB.

| Field | Meaning |
|---|---|
| `name` | Renames the share (rules as on create; `""` is a `400`, since a share has a name). |
| `password` | Sets or changes the password; `""` removes it. Any change revokes every access cookie and site grant issued before. |
| `expiresInSeconds` | Sets the expiry from now; `0` removes it. An expired share not yet swept can be rescued this way. |
| `applyInSeconds` | With a password or expiry change, schedules it that many seconds from now instead of applying it. The server applies it whether or not any client is online; a scheduled expiry counts from the apply time. One scheduled change per field: a new one replaces it, and an immediate change cancels it. |
| `cancelPending` | `"password"`, `"expiry"` or `"all"`: drops scheduled changes (first, before the rest of the request). |
| `entry`, `media`, `listing` | What the View link opens; applied at once, never scheduled. |
| `pinned` | `true` pins, `false` unpins. Re-pinning keeps the pin time. Not an edit: `modifiedAt` does not move. |
| `closed`, `note`, `notify`, `seenAt` | Inboxes only ([§ Receive Inboxes](#receive-inboxes)). |
| `sources`, `linked` | Linked shares only ([§ Linked shares](#linked-shares)). |

Nothing to change → `400`. A negative number → `400`. An inbox takes no `entry`, `media`,
`listing`, expiry, schedule or pin (`400`); the inbox fields on another share → `400`.

| Call | Behaviour |
|---|---|
| `DELETE /api/shares/{id}` | Deletes the share, rows first, then its bytes → `204`. |
| `POST /api/shares/delete` `{"ids":[…]}` | Deletes up to 1,000 shares → `200 {"deleted":[ids],"failed":[{"id","error","code"}]}` (both arrays always present). An id that is unknown, malformed or another account's fails alone with `not-found`. More than 1,000 → `413`; none → `400`. |
| `POST /api/shares/edit` `{"ids","password","expiresInSeconds","pinned"}` | Applies one password, expiry and/or pin change to up to 1,000 shares → `200 {"updated":[<share>…],"failed":[…]}`. Meanings as on `PATCH`; no other field is accepted. An inbox given an expiry or a pin fails alone. One bcrypt covers every share; every share pinned by one request shares one pin time. |
| `GET /api/downloads?id=<id>&id=…` | How many reads of the named shares are streaming right now → `{"active":N}`, summed over up to 1,000 ids (`400 bad-request` for none or more). Counts `/view`, `/download` and `/zip` (live shares included) from the first byte to the end; refusals, redirects and waiting pages are not reads, and neither is the owner's own bearer read. An id the account does not own counts 0. In memory: a warning before deleting something someone is pulling, never a lock. |

### What the View link opens

`/share/{id}` resolves to exactly one of four things:

- **the file itself**, for a share of one file (a `302` to `/view/{id}/{slug}`);
- **the file listing** (`listing:true`, or any share of several files with none of the others);
- **a page of the share** (`entry`: a relpath), which makes a folder of HTML a website (a `302` to
  `/site/{id}/<entry>`);
- **a gallery** (`media:true`) of the share's pictures and videos.

`listing`, `entry` and `media` are mutually exclusive, judged on the share a request would leave
(`400` when it would hold two), so `{"media":true,"entry":"","listing":false}` in one `PATCH`
turns a website into a gallery. The View URL never changes when the answer does. `?files=1` on
`/share/{id}` shows the listing whatever the share opens as.

**Galleries.** `media:false` is always accepted. `media:true` on an existing share is refused when
the share would not render as a gallery: `400 not-gallery-playable` when a file the gallery would
show is not one a browser plays (a HEIC photo or a `.mov`, judged by name as well as type),
`400 no-pictures` when no file is one, `400 share-incomplete` while files are still uploading. A
linked share is judged on its live walk. A share created with `media:true` and uploads is not
judged (its files are not there yet): the client uploads browser-playable files.

**Websites.** `entry` is not checked against the files when it is written, since at creation the
files are still pending; a value that names nothing falls back to the listing. A website stays on
the waiting page until every declared file has committed. `/site/{id}/{path}` answers for every
share whatever `entry` says (see [§ Public routes](#public-routes)).

### Text shares

`text:true` on create makes a **text share**: one text file the link opens as that file. A second
path, a file delete, a folder, a move and `entry`, `media`, `listing`, `sources` or `linked` →
`409 text-share`; a
manifest of more than one file, or `text` beside `receive`, `entry`, `media`, `listing` or a source
→ `400`. The one content change is a replacement (`?replaces=` or `?replaceAll=1`), so a link
already sent survives an edit. Name, password and expiry work as on any share.

`GET /api/shares/{id}/text` → `200 {"name","text"}`: the owner's text share's one file, `name` its
relative path and `text` its contents, for an editor that opens with the current words. It is JSON
(`Cache-Control: no-store`), never the file itself, so on the app origin the text stays data. Owner
only (another account's share, an administrator's included, `404 not-found`); a share that is not a
text share `409 not-text-share`; a text share with no file yet `404 not-found`; its file still
uploading `409 file-pending`; a file over 256 KiB, the apps' in-place edit limit,
`413 text-too-large`; bytes that are not UTF-8 `409 text-not-utf8`.

## Uploads

A file reaches a share through one of two routes: the **ranged PUT**, which is resumable and
takes a large file in parallel chunks, and the **batch**, one tar stream that commits many small
files in one request. Both are owner-only: another account's share answers `404 not-found`. A file
committed at a path the share already holds replaces it and keeps its slug, so links already sent
keep working; a path the share has never held simply joins it.

A committed file's bytes are at `shares/<id>/files/<relpath>` on the data volume. An upload in
flight is staged at `shares/<id>/parts/<sha256(relpath)>.part`, never under `files/`, and only the
server composes that name: a client that could name the staging path could splice its bytes into
another upload's part, or land a part where a served file belongs.

### The ranged PUT

`PUT /api/shares/{id}/files/{path...}` with three headers, all required:

- **`Upload-Session: <token>`**: 6 to 64 characters of `[A-Za-z0-9._-]`, chosen by the client. A
  staged part belongs to the session that started it: a chunk under another session (or with
  another total) discards what is staged and starts again, so two writers to one path are
  last-writer-wins and never a splice. A client that derives the token from the file's identity
  (its path, size and modification time, say) resumes an interrupted upload after a restart.
- **`Upload-Total: <bytes>`**: the file's size.
- **`Upload-Range: <start>-<end>`**: the bytes this request carries, end exclusive, with
  `0 <= start < end <= total`. The one zero-length range is `0-0` with `Upload-Total: 0`, an empty
  file, which commits at once.

The body is exactly those bytes. Chunks of one file may arrive in any order, at the same time, and
overlapping: a retried chunk rewrites the same bytes. The server writes each chunk at its offset
in the staged part and records the range only after the bytes are synced, in a `.ranges` sidecar.
A body that ends early records what landed.

- A chunk that leaves gaps → `202 {"missing":[[start,end],…]}`.
- The chunk that fills the last gap makes the server hash the whole file and commit it (rename,
  then the row) → `201 {"path","size","slug","sha256","viewable"}`. A client should compare
  `size` and `sha256` with its own.
- A chunk of an upload the same session already committed answers that commit's `201`.

Optional query parameters:

- **`?replaces=<old relpath>`**: once this upload commits, it takes over the old entry's slug and
  the old entry is removed, so a link already sent keeps working with the new content, even under
  a new name. A share whose page (`entry`) was the old path opens the new one. An old path the
  share does not hold → `400`, answered after the upload itself has committed.
- **`?replaceAll=1`**: once this upload commits, it is the share's only file: every other entry,
  pending entry and folder record is removed. Exactly one removed file with the same base name
  donates its slug; failing that, a sole removed file does; otherwise the fresh slug stands. A
  share named after its single old file is renamed after the new one.
- Both together → `400`.

Refusals, in the order the server checks them:

| Status | Code | When |
|---|---|---|
| `404` | `not-found` | Unknown share, or another account's. |
| `400` | `path-taken` | The path would list on top of an entry a linked source serves ([§ Linked shares](#linked-shares)). |
| `409` | `text-share` | A second path in a text share. |
| `415` | | A `Content-Encoding` other than `zstd` or `identity`. |
| `400` | | A missing or malformed `Upload-Session`, `Upload-Total` or `Upload-Range`; a relpath that is not valid; a body longer than its range; a chunk that would leave the upload holding more than 4,096 separate ranges; a body for an empty file. |
| `400` | `bad-body` | A `zstd` body that arrived whole and does not decode ([§ Compressed uploads](#compressed-uploads)). |
| `408` | `body-incomplete` | The body stopped arriving: it stalled past the limits above, or its connection ended first. What landed is recorded; ask the status route and send the rest. |
| `507` | `quota` | The declared total would pass the owner's quota (checked before staging and again in the commit transaction). |
| `507` | `no-space` | The chunk would dip into the server's free-disk reserve, or the disk filled while writing. |
| `409` | | The staged part changed under this chunk, the commit is between its rename and its row, or the part is gone. No code: ask the status route and send the missing ranges again. |

An uncoded `409`, a `5xx` and a dropped connection are worth retrying after asking the status
route; a `400`, `401`, `404`, `413`, `507` and a coded `409` are not.

### Where an upload stands

`GET /api/shares/{id}/uploads/{path...}?session=<token>` answers, for that session, in this order:

1. its own staged part: `{"offset":<bytes from 0 with no gap>,"complete":false,"total","missing":[[s,e],…]}`
   (an empty `missing` means every byte is staged and only the commit is left: send any range again
   to commit it);
2. its own commit: `{"offset":<size>,"complete":true,"size","slug","sha256","viewable","session"}`;
3. another session's staged part: `{"offset":0,"complete":false}` (another writer's progress is
   not this session's resume state);
4. anyone's commit: the shape of 2, with `session` naming the session that committed it;
5. otherwise `{"offset":0,"complete":false}`.

The resume loop: ask; if `complete` and `size` matches and `session` is yours, you are done; if
`complete` otherwise, send the whole file again; else send the `missing` ranges (the whole file
when none are named). A resumed upload must also check the local file is unchanged since its first
byte was sent: the protocol cannot see a same-size edit.

Staging nothing has written to for 3 hours (`HYPERDROP_ABANDONED_UPLOAD_TTL`) is removed with its
pending entry; if that leaves the share with nothing it is deleted, and the next chunk answers
`404 not-found`.

### Compressed uploads

The ranged PUT, the batch and `POST /api/shares/{id}/thumbs` accept `Content-Encoding: zstd`. The
server decompresses while it receives, and every number in the protocol stays in original bytes:
`Upload-Range`, `Upload-Total`, `missing`, `offset`, the committed `size` and `sha256`. Each request
body is its own complete zstd stream. A frame may declare a window of at most 64 MiB. A stream that
is not zstd, fails its checksum, declares too large a window or ends inside a frame although the
request body arrived whole → `400 bad-body`; any other encoding → `415`. Compression is a transport choice only: stored bytes, hashes and links never see it. A
client should skip it for content that is already compressed.

### Batch uploads

`POST /api/shares/{id}/batch` takes a tar stream (`Content-Type: application/x-tar` by convention;
the server reads the body as tar whatever it says), optionally `zstd`-encoded. Each regular entry
commits exactly as the ranged PUT would (hash, slug, quota check), in stream order. Directory
entries are skipped; any other kind of entry (a symlink included) → `400`. Caps: 2,000 files and
512 MiB per request, and 8,000 tar headers of any kind (`413` past one).

Every answer is `{"files":[<file>…],"committed":N}` listing what committed. When an entry fails,
processing stops there: the answer adds `"error"` (prefixed with the entry's name) and `"code"`
where one applies (the ranged PUT's codes), and its status is that refusal's (`400`, `408`, `409`,
`413`, `507`); a stream that ends early is `408 body-incomplete` when the body stopped arriving and
`400 bad-body` when it arrived whole. The committed prefix is always reported, so a retry sends only the rest. A batch is not
resumable: use it for small files and the ranged PUT for large ones.

### Early links

`POST /api/shares` may declare the files a share will hold before any byte is sent (`files`, see
[§ Creating a share](#creating-a-share)). Each declared file becomes a **pending** entry with its
slug already minted, so every link of the share is valid at once. Until the bytes arrive:

- `/view` or `/download` of a pending file serves a small **waiting page** that polls
  `GET /share/{id}/status`, shows the upload's progress, and reloads into the file the moment it
  commits.
- `/share/{id}` and `/zip/{id}` serve the waiting page for the whole share while any file is
  pending, so a visitor never sees a half-uploaded folder or website.
- A pending file's `size` is the declared one, it has no `sha256`, and its `viewable` is judged by
  its name alone.

When the upload commits, the entry keeps its slug and loses `pending`. A file that arrives under
another name than it was declared with commits with `?replaces=<declared path>` and takes over the
declared entry's slug.

`PUT /api/shares/{id}/preparing/{path...}` `{"fraction":0.75,"stage":"encoding"}` lets the sender
report that a pending file's bytes are still being made (a video still being re-encoded):
`fraction` from 0 to 1, `stage` `encoding` or `remuxing`, body at most 1 KiB → `204`. A path that is
not a pending entry → `404 not-found`. Reports live in memory only. The status route shows a report
under 5 minutes old, and the empty-share sweep treats a report from the last hour as a sign the
share is alive.

`GET /share/{id}/status?slug=<slug>` is public, gated by the share's access cookie only (no
`?pw=`, no password form: a protected share without a valid cookie gets a bare `401` JSON), and
answers on both origins so the waiting page can poll it from either:

```json
{"complete":false,"uploadedBytes":1048576,"totalBytes":8388608,
 "counts":{"total":3,"completed":1,"pending":2},"preparing":0,
 "files":[{"slug":"…","path":"a.mp4","size":4194304,"bytes":1048576,"complete":false,
           "preparing":{"stage":"encoding","fraction":0.5}}],
 "truncated":true,"file":{…}}
```

`files` carries at most 500 entries (`truncated:true` past that). A pending file's `bytes` (staged
bytes, counting chunks still arriving) is measured only when the share has 64 files or fewer or the
file is the one `?slug=` names, so on a larger share `0` means "not measured". `?slug=` repeats
that file's entry as `file`. A linked share whose source cannot be read answers
`{"unavailable":true}`. `Cache-Control: no-store`. Unknown, expired and inbox shares → `404`.

### Upload speed probe

`POST /api/speedtest` takes a raw body of any type, counts it and throws it away →
`200 {"bytes","seconds"}`. Any signed-in account; no quota is charged. At most 64 MiB
(`413 body-too-large` past it) and 30 seconds: a body still arriving then is answered with what
arrived and the connection is closed. One probe at a time per server (`429 speedtest-busy`). The
rate that matters is the client's own measurement, which includes bytes still in flight.

## Files and folders in a share

Each of these answers `200` with the updated share view (`404 not-found` for an unknown share or
another account's). Paths are validated like an upload's (`400` otherwise).

| Call | Behaviour |
|---|---|
| `DELETE /api/shares/{id}/files/{path...}` | Removes one file: its row, its bytes and its gallery tile. Its slug dies with it (its links answer `404`); the share and its other links keep working. When it was the share's `entry`, the link falls back to the listing. A pending entry's staged bytes go with it. Unknown path → `404 not-found`, naming the file; a text share → `409 text-share`; a linked entry → `409 share-linked`. |
| `POST /api/shares/{id}/move` `{"from","to"}` | Moves one stored file, or every stored entry under a folder, replacing `from` with `to`. Every moved entry keeps its slug, hash, dates and type, so links already sent keep working; `/site` addresses follow the path. The `entry` page and folder records under `from` move with it. `to` equal to `from` or under it → `400 into-itself`; nothing stored at or under `from` → `404 not-found`; a linked entry under `from` → `409 share-linked`; a moved file still uploading → `409 share-incomplete`; a destination that exists (stored, a folder record, or listed by a source) or sits under a file → `400 path-taken` (folders are never merged); an inbox → `409 receive`; a text share → `409 text-share`. |
| `POST /api/shares/{id}/folders` `{"path"}` | Records one explicit folder, which lists (and stays) even when empty. Parents are not recorded; a folder a file's path passes through is never a record. A file at the path, a path under a file, or a folder that already exists → `400 path-taken`; a name a linked source lists → `400 path-taken`; 1,000 records already → `400 too-many-folders`; an inbox → `409 receive`; a text share → `409 text-share`. |
| `DELETE /api/shares/{id}/folders/{path...}` | Removes the folder records at the path and under it. A stored file at or under it → `409 not-empty` (delete the files first); no record → `404 not-found`; an inbox → `409 receive`; a text share → `409 text-share`. |

A zip holds files only, so an empty folder is not in it.

## Previews and gallery records

The server never decodes a picture or a video frame to make a preview. What a gallery or a link
preview shows beyond names and sizes is uploaded by the owner's client: a **poster** (one frame for
the whole share), **gallery tiles** (one small JPEG per file) and **gallery records** (each file's
pixel size, duration and capture time). None of them is a file entry: they take no slug, no
listing row, no zip entry and no quota byte, and none moves `modifiedAt`. A gallery with none of
them renders from the full-size files as square tiles in name order.

| Call | Behaviour |
|---|---|
| `PUT /api/shares/{id}/poster` | Stores the share's poster: a raw JPEG body, at most 4 MiB → `204`. Empty or larger → `413` (no code); a body that does not decode as a JPEG → `400`, since the public card route serves it as `image/jpeg`. Stored while the share holds one entry, the poster records that entry, and the public card stops showing it once the entry is deleted or hidden. |
| `DELETE /api/shares/{id}/poster` | Removes the poster → `204` whether or not one was stored; another account's share → `404`. The public card then answers `404` and `og:image` falls back to the brand or generic tile. |
| `GET /api/shares/{id}/poster` | The poster as `image/jpeg` (`Cache-Control: private, max-age=3600`), for the owner's own thumbnails, protected shares included. None → `404 not-found`. |
| `PUT /api/shares/{id}/thumbs/{slug}` | Stores one file's gallery tile: a raw JPEG, at most 512 KiB (`413 thumb-too-large`) → `204`. A slug the share does not hold → `404 not-found`; a body that is not a JPEG → `400`. |
| `POST /api/shares/{id}/thumbs` | Many tiles in one request: a tar of `<slug>.jpg` entries (`zstd` accepted), at most 2,000 entries and 256 MiB. An entry over 512 KiB, naming a slug the share does not hold, or not a JPEG is skipped → `200 {"stored":N,"skipped":[names]}`. Past a cap → `413` and a broken stream → `400`, both of the same shape, `stored` counting the tiles already written. |
| `GET /api/shares/{id}/thumbs/{slug}` | One tile as `image/jpeg`, for the owner, protected shares included. No tile → `404 not-found`. |
| `PUT /api/shares/{id}/gallery` `{"items":[{"slug","w","h","durationMs","takenAt"}]}` | Records gallery metadata, merged by slug: a slug the request names takes the request's values whole, every other row stays. A width or height outside 1-131,072 or a duration outside 1 ms-24 h is stored as unknown. Items naming a slug the share does not hold are dropped → `200 {"items":N,"dropped":M}`. At most 4 MiB (`413 body-too-large`). A row goes when its file leaves the share. |
| `POST /api/shares/{id}/download-ticket` `{"slug"}` | A single-use URL for one file of the caller's own share, for a client whose credential does not reach the files origin (the web client's session cookie) → `200 {"url"}`: `https://files.<domain>/download/<id>/<slug>?t=<ticket>` (the request's own origin when the server has no split origins). The ticket is 32 random bytes kept in memory only, valid 2 minutes, spent by its first use, and bound to the account, the share, the slug and the token that asked for it (the web session or the device token): it is honoured only while that token is still signed in (a web session inside its limits and while the web client is on), so a sign-out, a revoke, a password change or the switch leaves an unspent ticket dead. At most 64 live tickets an account and 4,096 a server, past either `429 too-many-tickets` with `Retry-After: 5`. `/download` honours it exactly where it honours the owner's bearer (an inbox's files and a password-protected share included); every other route ignores `t`. Another account's share (an admin's too), an unknown share or a slug the share does not hold → `404 not-found`; a file still uploading → `409 file-pending`. A HEAD with the ticket honours it without spending it. |

The public side of previews is described in [§ Link previews](#link-previews).

## Receive Inboxes

A **Receive Inbox** is a share strangers upload **into** through a public page, `/receive/{id}`,
and whose content only its owner reads. On the wire it is a share with `receive: true`; the listing
filter is `?kind=receive`, and a full inbox answers `receive-full`.

**Its content is never served publicly.** Every public read route (`/share`, `/view`, `/download`,
`/zip`, `/site`, `/thumb`, `/card/{id}/poster.jpg`, the status poll) answers an inbox's id with
`404`, as if it did not exist. The one way to read what an inbox holds is the owner's own
authenticated fetch on `/download/{id}/{slug}` with `Authorization: Bearer`; `/view` stays `404`
even then, so nothing a stranger uploads ever renders as a page on any origin.

### Creating and editing an inbox

`POST /api/shares` `{"receive":true,"name","note","maxBytes","maxFiles","password"}`:

- `name` is required: it titles the upload page.
- `note` (at most 500 characters) is shown on the upload page.
- `maxBytes` (`0`: no cap of its own; the owner's quota still applies) bounds what the inbox holds
  in total. `maxFiles` (`0`: the server's bound) bounds its file count, and can only lower the
  server's bound of 10,000 files; a larger value is stored as 10,000. Negative caps → `400`.
- `password` gates the upload page exactly as it gates a share.
- A manifest, an `entry`, an expiry, a reservation, `media`, `listing`, `text` or a source beside
  `receive` → `400`. An inbox has no expiry: closing it is the off switch.

`PATCH /api/shares/{id}` takes, on an inbox only (`400` on any other share):

- `closed`: `true` closes the upload page, `false` reopens it;
- `note`;
- `notify`: whether arrivals are announced on the owner's devices (on by default);
- `seenAt`: the owner's read mark. It only moves forward (the server keeps the later of the stored
  and the sent time), so a device running behind cannot rewind another's. Files committed at or
  before it are not new.

`name` and `password` change as on any share. The caps cannot be changed after creation.

An inbox's share view always carries `notify` (`true` or `false`, never absent), and `seenAt`
once set. The owner's reads (`GET /api/shares/{id}` and the inbox listing) add `incoming`, the
uploads in flight: `[{"name","bytes","total","by"}]`, `bytes` being what has landed so far and
`total` what the sender declared. The owner's watch answers the same entries as they move
([§ Watching for changes](#watching-for-changes)), and an upload leaves `incoming` before its
commit is journaled, so a row read after an upload ends never shows it arriving. `by`, and
`uploadedBy` on a committed file, group one sender's files: they carry the sender's grouping
token (below), empty for a sender without one. None of this appears on any public route.

The default listing leaves inboxes out; `GET /api/shares?kind=receive` lists only them. The
empty-share sweep never deletes one, and anonymous uploads are charged to the inbox owner's quota.

### The public upload page

`GET /receive/{id}` serves the page: the inbox's name, its note and a drop zone whose script
uploads each picked file with the PUT below and shows its progress. It never lists what the inbox
already holds. A closed inbox, and an open one holding as many files as it takes, render the page
in that state (`200`). A protected inbox shows the password form first (the same access cookie and
lockout as a share; `?pw=` works). An ordinary share's id → `404`. A link unfurler gets a card with
the name and note.

`PUT /receive/{id}/files/{name}` is the server's one anonymous write. The checks, in order:

1. the id is an inbox (`404` otherwise);
2. a protected inbox needs a valid access cookie (`401` JSON otherwise; no password form);
3. the inbox is open (`403 closed`);
4. `{name}` is one path segment, NFC, valid UTF-8, with no control character and no bidirectional
   formatting character, since the owner reads it in a notification and a terminal (`400`
   otherwise);
5. no `Content-Encoding` (`400`) and a `Content-Length` (`411`), so the caps are checked before
   the first byte;
6. the caps: the inbox's file count and `maxBytes` (`413 receive-full`);
7. the owner's quota (`507 quota`), before anything is staged or declared;
8. a slot among the anonymous uploads in flight: at most 16 into one inbox, 8 from one address
   (an IPv6 address by its /64) and 64 on the server (`429 rate-limited` with `Retry-After: 10`,
   refused rather than queued);
9. the disk (`507 no-space`): the whole file must fit what is usable now, and while it lands it
   holds a rolling window of at most 64 MiB, admitted again as its bytes arrive, with anonymous
   uploads together holding at most half the usable space (a window refused mid-body ends the
   upload with its part and row removed); and, at commit, the owner's quota (`507 quota`, in the
   same words as step 7) and the caps again (`413 receive-full`), so a file over a cap never
   commits.

A `{name}` the inbox already holds, or one another upload in flight has claimed, is renamed
(`report.pdf` → `report 2.pdf`, up to `report 1000.pdf`; a name taken that often →
`413 receive-full`), so a second sender never overwrites the first. A body that sends nothing for
a minute, or whose connection ends first, ends the upload with `408 body-incomplete`, its staging and
pending row removed. → `201 {"name","size"}`:
no slug, nothing an uploader could fetch back.

**The sender's grouping token.** The upload page sets `hdv_<id>`: 16 random bytes as base64url,
`HttpOnly`, `SameSite=Lax`, `Secure` under TLS, host-only, scoped to `Path=/receive/<id>`, for 12
hours. The PUT only reads it, never mints one (minting there would turn one cookieless sender into
one group per file), and only a value in the minted shape is recorded. It carries **no authority**:
no gate reads it, and a protected inbox still asks every upload for the access cookie.

## Linked shares

A **linked share** serves a folder or file that already lives on the server's own disk (a NAS
shared folder, say), live, without copying it. Nothing is uploaded and no quota is charged; the
share lists what the folder holds at the moment it is read.

### What a linked share may reach

Two boundaries decide it, and they answer different questions:

- **The server's roots** decide what this install may ever read: `HYPERDROP_LINKED_ROOTS` (fixed
  directories, each named by its base name) and `HYPERDROP_LINKED_SCAN` (parent directories whose
  readable top-level subdirectories each become a root of their own name), see
  [`docs/configuration.md`](configuration.md#environment-variables). A path is written root-relative:
  `photos/2024` is the folder `2024` inside the root named `photos`. The roots gate **every serve**.
- **An account's `sourceRoots`** allowlist decides which of those an account may share from. It
  gates **creating** a linked share and browsing. An administrator has no allowlist: it reaches
  every root. Narrowing an account's list (or demoting it) revokes the existing sources it no
  longer covers, and widening it restores them, links unchanged (see
  [§ Accounts (admin)](#accounts-admin)). The verdict reads the list alone, so a volume that is
  unmounted this minute revokes nothing.

A candidate path is checked in this order: not a clean relpath, or any segment starting with
`.`, `@` or `#` (names no share ever lists) → `400 bad-source`; outside the caller's reach →
`403 source-forbidden`; nothing on disk → `404 source-missing`.

Every byte of a linked share is opened through an `os.Root` rooted at the server root that holds
the source, so a symlink planted inside cannot reach anything outside it. The walk never enters a
symlinked directory; a symlinked file is listed only when its target is a regular file inside the
same source and no hop passes a hidden name.

### Browsing the server's folders

| Call | Behaviour |
|---|---|
| `GET /api/sources` | *Compressed.* `{"roots":[{"path","name"}]}`: every server root for an administrator; for anyone else, each `sourceRoots` entry whose root is currently present. `?all=1` is an admin-only assertion: it changes nothing for an administrator and is `403 source-forbidden` for anyone else. |
| `GET /api/sources/browse?path=<root-relative>` | *Compressed.* One level of a folder: `{"path","dirs":[{"name","mtime"}],"files":[{"name","size","mtime","viewable"}],"truncated"}`. Hidden names and every symlink are left out. At most 1,000 entries (`truncated:true` past it); the read itself is bounded, so a truncated answer is a sorted window of the folder, not its alphabetically first names. A folder's `mtime` is the newest modification time among the files directly inside it (reading at most 2,048), or its own when it holds none. A path that is a file → `404 source-missing`. |
| `GET /api/sources/file?path=<root-relative>` | *Compressed.* One file's bytes, to look at a pick before it becomes a share: `Content-Disposition: attachment`, `Content-Type` from the name, `Cross-Origin-Resource-Policy: same-origin`, Range and conditional requests. A folder → `400 bad-source`. Nothing is created or charged. |

### Creating and editing one

`POST /api/shares` takes `"source":"<root-relative path>"` or `"sources":[…]` (both together →
`400 bad-source`). Every path passes both boundaries and must resolve, or the whole share is
refused with that path's code. Two sources with one base name → `400 bad-source`. A source
alongside `receive` → `400 source-exclusive`: an inbox holds only what strangers send. A source may
sit beside a `files` manifest and uploads; a manifest path that would list on top of a source's
entry → `400 path-taken`. With `media:true` the gallery gate reads the first walk, and a refusal
deletes the share it just made. → `201` with the share view, the first walk included.

`PATCH /api/shares/{id}` takes:

- **`sources`**: the whole list, validated as on create (`[]` removes every source);
- **`linked`**: what each source **shows** of its walk:
  `{"linked":{"<source>":{"fixed":true|false,"hide":["<rel>"],"show":["<rel>"]}}}`, paths relative
  to the source. `fixed:true` walks the source now and fixes it to what it holds (doing it again
  re-takes the snapshot); `fixed:false` returns it to live. `hide` takes a file or folder out of
  what the source shows, matched on a path-segment boundary, without touching the disk; `show`
  undoes it. A hidden entry's link dies, and comes back with the same slug when it is shown
  again. Applied after `sources`, so a source added in the same request can be filtered in it.
  Refusals: a key that is not one of the share's sources → `400 not-a-source`; a `hide` path that
  is not clean → `400 bad-source`; fixing a revoked source → `409 source-revoked`, an unreadable
  one → `404 source-missing`, one whose walk passes 10,000 entries → `400 source-too-big-to-fix`;
  more than 20,000 filter paths across the share → `413 linked-filter-too-big`; on an inbox →
  `400 source-exclusive`.

### How it lists and serves

- The file list is a **live walk** taken on every read, capped at 10,000 entries, never stored. A
  public read reuses a walk for up to 2 seconds.
- A linked entry's slug is minted the first time its path is listed and kept for the life of the
  share, so a file that disappears and comes back serves under the same link. A source removed
  from the share takes its slugs with it.
- With **one** source the entries list bare. With **several**, each lists under its source's base
  name (a folder's files below it, a file as itself); a share that gains a second source moves its
  entries under that name, slugs and all, so a link copied before still serves the same file.
- Linked entries carry `"linked":true`, `committedAt` is the file's modification time, and they
  have no `sha256` or `addedAt`. A stored upload at the same relpath shadows the linked entry.
- **Uploads beside sources** are allowed: a ranged PUT, a batch and a folder record are accepted,
  and only a path that would list on top of an entry a source serves is refused
  (`400 path-taken`). Deleting or moving a linked entry → `409 share-linked`: it belongs to the
  folder, not to the share.
- `totalSize` counts stored and linked bytes alike; the owner's quota and `GET /api/usage` count
  stored bytes only.
- **When no source can be read** (unmounted, permissions changed), the share view carries
  `sourceMissing:true`, every public page of the share answers a "not available on this server"
  page (`200`, `no-store`) rather than `404`, and the status poll answers `{"unavailable":true}`.
  The owner's bearer fetch on `/download` answers `404 source-missing` instead, since a client
  would save the page as the file. A subfolder that cannot be read is skipped and the rest lists.
- A revoked source lists and serves nothing; when every source is revoked or missing, the share
  reads as unavailable.
- `/zip/{id}` of a share with a source streams without `Content-Length`, the folder's files being
  read as the archive is written; a file gone mid-stream is skipped.
- The empty-share sweep never deletes a linked share.

The share view reports each source under `linked`, keyed by the source path:
`{"fixed":true,"hidden":3,"revoked":{"at":"…","files":12}}`, each part *omitted when empty*; a
source with no filter and no revoke is absent. `revoked.files` is how many entries the source
listed when it was revoked, omitted when it could not be read then.

## Live shares

A **live share** publishes its links at once and serves every byte on demand from the sharer's
own running client: the server relays and stores nothing, and charges no quota. While nobody
downloads, nothing moves. A live share lives in the server's memory, not its database, and ends
when its sharer ends it or stops answering for longer than the grace period
(`HYPERDROP_LIVE_SHARE_GRACE`, 5 minutes by default).

Every route here takes the bearer token and is owner-scoped; an id the caller does not own answers
`404`, indistinguishable from an unknown one. JSON bodies are at most 64 MiB
(`413 body-too-large`) and decoded strictly.

### Creating one

`POST /api/live-share`
`{"name","folder","password","zipSize","listing","entry","files":[{"path","size","mime","mtime"}],"resume"}`

- `files` is required and is the whole share: at most 100,000 entries (`413 manifest-too-big`),
  each path a valid relpath and unique, each size not negative (`400` otherwise). `mime` is the
  sharer's type for the file (an unparseable one is served as `application/octet-stream`); `mtime`
  is RFC 3339.
- `name` follows the rule a stored share's name does; `password` works as on a stored share.
- `zipSize` is the exact length of the share's zip as the sharer's client will produce it, which
  lets `/zip/{id}` declare `Content-Length`; it is not echoed back.
- `listing:true` forces the listing for one file; `entry` (one of `files`) makes the link open that
  page; the two together → `400`. A gallery is chosen later with `PATCH`.
- `resume` re-attaches to a share the caller still owns inside its grace period, keeping its id,
  slugs, name, password and choices: the manifest must match exactly (`folder`, `zipSize` and every
  file's path, size, type and mtime) or → `409 live-share-resume-mismatch`; an ended or unknown one
  → `404 live-share-ended`. → `200` with the share view.

A new live share → `201` with the same share view a stored share answers, every file's slug
minted, its `viewable` judged from the sharer's type (the server never sees the bytes to sniff
them). Nothing in any response marks a share as live. At most 3 live shares per account
(`429 too-many-live-shares`); a new one also spends a token of the share-creation rate limit
(`429 rate-limited`, administrators exempt), checked first.

### Serving it

| Call | Behaviour |
|---|---|
| `GET /api/live-share/{id}/jobs` | The sharer's long poll for work. Parks up to 20 seconds, then → `{"jobs":[{"job","kind","path","start","end"}],"visitors":N}` (`jobs` never `null`, at most 256 per answer). `kind` is `file` (with `path`, `start` and `end`, `end:-1` meaning to the end) or `zip` (`path` is the folder of a `?dir=` zip, empty for the whole share). An unclaimed job is offered again on every poll until it is claimed or failed, so a client de-duplicates by `job`. `visitors` is the share's visitor count. While a poll is parked the share is online. |
| `POST /api/live-share/jobs/{job}` | The bytes for one job, with `Content-Length` set (the range's length, or `zipSize`). The server pipes the body straight into the waiting visitor's response and keeps no copy; a slow visitor slows the sharer's upload by TCP backpressure. → `200 {"ok":true}`. A body that ends short, stalls (60 seconds without a byte), or whose visitor leaves → `400` "transfer interrupted", and the visitor sees a broken response rather than a short file. A job that is unknown, another account's, already claimed or abandoned → `404`. |
| `POST /api/live-share/jobs/{job}/error` `{"code"}` | The sharer cannot serve this job → `200 {"ok":true}`. `code` is a short string, at most 4 KiB of body; empty → `400`. The visitor's answer depends on it: `live-share-ended` → `404`; `source-changed` (the file changed on the sharer's device) and `source-gone` (it is no longer there) → `409` with a plain-text sentence; anything else → `503` as for an offline sharer. |
| `PATCH /api/live-share/{id}` | Changes a running share → `200` with the share view. `addFiles` adds files (a path already served is replaced in place and keeps its slug); `replaceFiles` swaps the whole manifest, keeping the slugs of paths it still holds (not together with `addFiles`); `zipSize` replaces the archive length, together with a file list only; `listing`, `media` and `entry` set what the link opens (one at most on the resulting share; `media:true` passes the gallery checks); `name`; `password` (`""` removes it, and any change revokes existing cookies); `expiresInSeconds` (`0` removes the expiry). Nothing to change → `400`; the manifest checks of create; more than 100,000 files in the resulting share → `413 manifest-too-big`. A refused request changes nothing. The caller must already be serving any path it adds. |
| `DELETE /api/live-share/{id}` | Ends the share → `200 {"ok":true}`; every job still waiting fails with `live-share-ended`. Deleting the account ends its live shares too. |

### What a visitor sees

The public routes reach a live share through the same gate as a stored share (password, expiry,
suspended owner, no-embed), falling back to the live registry when no stored share has the id.
`/site` relays a live website's pages and assets. The differences are all in serving bytes:

- **The sharer is offline** (no parked poll for 10 seconds): `/view`, `/download`, `/site` and
  `/zip` answer `503` with `Retry-After: 30` and a plain-text sentence. The listing still renders,
  with an offline note.
- **A visitor waits up to 30 seconds** for the sharer's client to take the job; past that, `503`.
- **A share holds at most 8 visitor transfers at once**, waiting or streaming; one more answers
  `503` with `Retry-After: 5` and never reaches the sharer. One visitor address (an IPv6 address
  by its /64) holds at most 2: its further requests wait up to 30 seconds for one of its own to
  end, and then get the same `503`.
- **The ETag** is `"<size>-<mtime in Unix nanoseconds>"`, from the manifest. It is strong because
  the sharer's client re-checks size and mtime before every transfer and refuses to serve a file
  that changed.
- **Range** takes a single range only (`bytes=a-b`, `a-`, `-n`); several ranges, an unparseable one,
  or one starting past the end are answered with the whole file (`200`). `If-Range` compares the
  ETag.
- **HEAD** is answered from the manifest and never reaches the sharer.
- **No compression**, ever.
- **Link unfurlers** get the card, never a job; a live share's card never offers the video itself.
- **`/zip`** declares `Content-Length` only for the whole share and only when `zipSize` was sent;
  it is not resumable.
- A failure after bytes have started has no status left to change: the visitor sees a truncated
  response.

## Server administration

### Health

`GET /api/health` takes no authentication and answers on every host and on port 80 as well:

```json
{"status":"ok","version":"1.0.0","serverID":"…","arch":"amd64",
 "domain":"share.example.com","updateOverAPI":true,"sources":true}
```

| Field | Meaning |
|---|---|
| `version` | The contract version ([§ Versions](#versions-and-the-client-header)). |
| `serverID` | A stable, non-secret identifier of this install, derived from the volume secret: it survives restarts, updates and address changes, and changes with a fresh data volume. A client that bound a saved server to a `serverID` should refuse it when the same address later answers another one (or none): the box was replaced and its shares are not the ones the client knows. |
| `arch` | The architecture the binary was built for (`amd64`, `arm64`), so a client updating the server sends the matching build. |
| `domain` | The domain the server serves, so a client that joined by IP address can move its links onto the name, after checking that the name answers with the same `serverID`. A free name is reported only once it is connected. Omitted when there is none. |
| `updateOverAPI` | `true` when `POST /api/server/update` can work here (the install has the root updater). |
| `channel` | The install manager that owns the binary (`synology`: update it in Package Center). |
| `platform` | `dsm7` or `dsm6` on a Synology package. |
| `sources` | `true` when the server has at least one linked-share root. |
| `web` | `true` when `/app` serves the [web client](#the-web-client): its switch is on and a bundle this server serves is installed. |

It deliberately carries nothing about load, disk or accounts.

### Usage and logs

| Call | Behaviour |
|---|---|
| `GET /api/usage` | Admin. `{"mode":"vps","totalBytes","usedBytes","freeBytes","hyperdropBytes","reservePercent","reserveBytes","health","shares":{"count"}}`, plus `memTotalBytes`, `memAvailableBytes` and `load1` when the system reports them. The disk figures are for the filesystem holding the data directory; `hyperdropBytes` is what every share stores. `health` is the server's own verdict (below). A `user` reads its own figures from `GET /api/me`. |
| `GET /api/admin/log?tail=N&skip=K` | Admin. The last `N` lines (default 2,000, at most 5,000) of the server's log as `text/plain`, leaving out the newest `K` (default 0), which is how a reader pages back; a value that is not a non-negative number → `400 bad-request`. The log holds boot, shutdown, housekeeping, certificate and address events, and every response of status 400 or more as the route's **pattern**, its status, its code and the share id, never the request path, so no token or password reaches it. |

`health` is `{"level":"ok"|"warn"|"critical","reasons":[{"code","text"}]}`, the worst of these
signals, each failing one adding a reason with a stable code and a sentence:

| Signal | `code` | Warn | Critical |
|---|---|---|---|
| Disk | `disk-low` | room for new shares (free space minus the reserve) under 100 MB, whatever the disk's size | free space under the reserve, where uploads fail |
| Memory | `memory-low` | under 15% available | under 8% |
| Restored database | `db-recovered` | the last boot restored the database from a backup (for a week; the text names the backup's date) | never |
| Missing files | `files-missing` | a daily pass (and the boot) found stored files absent from disk; the text counts them and says to restore the data folder from a backup | never |
| PROXY header | `proxy-header` | 3 or more PROXY headers from public addresses within the last hour; the text never names them | a private source sent a header it may not (an unlisted proxy) or a listed proxy sent none; the text names the address and the fix |
| Address change waiting | `address-pending` | an address change asked for on the Synology package (`HYPERDROP_ADDRESS_REQUEST`) waits until the new address is proven; the text names it and why | never |

There is no share-count ceiling: nothing the server holds in memory grows with the number of
shares.

### Updating the server

| Call | Behaviour |
|---|---|
| `GET /api/server/settings` | Admin. `{"autoUpdate","selfUpdate","updateAvailable","desktopSignIn"}`, plus when known `latest` (the newest released version), `checkedAt`, `failed:{"version","reason","at"}`, `lastAutoUpdate:{"from","to","at"}` (for 14 days) and `notices:[{"key","title","body"}]`, the update reminders due now. `selfUpdate` is what the server will do: `on` (it installs releases itself), `off` (an administrator turned that off), `failed` (the newest release failed to install), `manual` (it cannot install on its own: no root updater, the release check is off, or the build is not official) or `nas` (Package Center updates it). `webApp` is the [web client](#the-web-client): `{"enabled","installed"}`, plus when known `version` and `build` (the installed bundle), `latest` (the version the last read of the web manifest picked, or the current install's when that is newer and still served), `checkedAt` and `failed` (why the last fetch failed). `desktopSignIn` is whether a computer may [sign in with a phone](#signing-a-computer-in-with-a-phone): `true` unless an administrator turned it off. |
| `PATCH /api/server/settings` `{"autoUpdate":bool,"webApp":bool,"desktopSignIn":bool}` | Admin, the bearer alone: the box only ever installs a release its own binary verifies, whatever this says. Any field may be left out, not all three. → the `GET` document. Turning `autoUpdate` on clears a recorded failure and checks at once. Turning `webApp` off signs every web session out; turning it on fetches the web manifest at once. Turning `desktopSignIn` off drops every computer's sign-in request waiting. A body that names none or is otherwise malformed → `400 invalid`; `autoUpdate` on a Synology package, a server that cannot install on its own, or a build that is not official → `409 self-update-unavailable`, and then no switch moves. `webApp` and `desktopSignIn` switch on every server. |
| `POST /api/server/update` | Admin, never judged against the version window (it is how a server that is too old is fixed). The body is the new server binary, uncompressed, at most 256 MiB. Headers: `X-HyperDrop-Password` and `X-HyperDrop-TOTP` (the step-up, carried in headers because the body is the binary), `X-HyperDrop-Signature` (the release signature file, standard base64), and optionally `X-HyperDrop-Arch`. → `202 {"staged":true,"bytes","startedAt"}`; the swap, the restart and the health check happen after the response, so watch `GET /api/health` for the new `version`. |

`POST /api/server/update` refuses, in this order: no update directory here →
`501 update-unsupported`; the caller has no second factor → `403 totp-setup-required` (this route
hands over root on the box, so it never rests on one factor); the step-up refusals; another
architecture → `400 arch-mismatch`; a signature header that is not base64 → `400 bad-signature`;
then while staging: a body that broke off → `400`; over 256 MiB → `413 body-too-large`; not an ELF
binary → `400 not-a-server-binary`; no signature → `400 unsigned-binary`; a signature that does not
verify (another key, other bytes, another architecture, an older version) → `400 bad-signature`;
the database backup taken before every update failed → `500 backup-failed`. How the staged binary
is then verified and installed as root is in [`docs/security.md` § Updates](security.md#updates).

| | |
|---|---|
| `POST /api/server/update/latest` | Admin, for a client with no binary to send (the web client). The body is JSON `{"currentPassword","totp"}`, decoded strictly. The server reads its release manifest and stages the newest release through the same download, length, SHA-256, decompression-bound and release-signature checks as its daily self-update, whether or not automatic updates are on. Refuses, in this order: a box that cannot install a release itself (a NAS, no root updater, an unofficial build) → `501 update-unsupported` with the reason; the caller has no second factor → `403 totp-setup-required`; the step-up refusals (an elevated web session skips only the code); a release already staged and waiting for the installer → `409 update-in-progress`; the manifest or the release could not be fetched or verified → `502 update-failed`. Already on the newest → `200 {"updated":false,"reason":"already current"}`; staged → `202 {"version"}`, and the swap, restart and health check follow the response as for `POST /api/server/update`. |

### The web client

The server serves the web client, a separate product, at `/app` on the app origin: a signed
bundle of static files it installs into its data directory (`web/`). It reads the web release
manifest (`HYPERDROP_WEB_RELEASES`, [`docs/configuration.md`](configuration.md)) 30 seconds after
boot, then about once a day and whenever an administrator turns the web client on, on every
install whatever its automatic-update switch says, and installs the newest bundle whose contract
has the server's own `MAJOR.MINOR`, else the newest one minor below; never one of a newer minor,
and never one older than a current install that still serves the server (it moves to an older
bundle only when the current one no longer serves the server's contract; `PUT /api/server/web`
may install an older one). A
bundle's Ed25519 signature covers its version, build, contract, SHA-256 and size, and must be made
by a web release key. The install before the current one is kept; older ones are removed.

An administrator's switch, on unless turned off, decides whether `/app` serves it: `webApp` in
`GET /api/server/settings` and `PATCH /api/server/settings` (above). Turning it off signs every
web session out, and while it is off every web session is refused as an unknown one (`401`) and
the sign-in answers `403 web-off`. While no bundle is installed, or while the installed bundle's
contract is one this server no longer serves (after a server update, until a newer bundle is
fetched), the web session routes answer `503 web-unavailable`. In all three cases `/app` answers
the server's own page saying which (`503`). `DELETE /api/web/session` answers `204` whatever the
switch and the bundle say, so a session can always end. `GET /api/health`
reports `"web":true` while `/app` serves the web client.

| Call | Behaviour |
|---|---|
| `GET /app`, `GET /app/{path...}` | No auth. `/app` → `308` to `/app/`. A path naming a file of the bundle answers it (its `.gz` sibling, `Content-Encoding: gzip`, when the request accepts gzip); a path with no extension that names no file answers `index.html`, the client's router; anything else → `404`. `index.html` is `Cache-Control: no-store`, `assets/…` `immutable`. Every answer carries `Content-Security-Policy` (the page's own script and WebAssembly, no inline script or style, images and media also from `files.<domain>`), `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin` and a `Permissions-Policy`. `GET` and `HEAD` only. |
| `PUT /api/server/web?version=V&build=N&contract=C` | Admin, the bearer alone. Installs a bundle by hand, for a server that cannot reach the manifest: the body is the archive (`hyperdrop-web-<version>.tar.gz`, at most 64 MiB), `X-HyperDrop-Signature` its signature file's base64. Verified exactly as a fetched bundle → `200 {"version","build"}`. A signature that does not verify for these parameters, a parameter that is malformed or an archive that is not a plain tree of files with `index.html` at its root → `400 web-bundle-invalid`; a contract this server does not serve → `409 web-bundle-outside-window`; over 64 MiB → `413 body-too-large`; a server with no place to install it → `503 web-unavailable`. |

### The server's domain

| Call | Behaviour |
|---|---|
| `GET /api/domain` | Admin. `{"domain","ip"}`: the domain served (`""` for none) and the server's public IPv4 (`""` behind NAT or without a domain), the address a domain's `A` records must point at. Adds `certStatus` once certificate events were recorded: per name, `{"state":"pending"|"issued"|"failed","lastError","lastAttempt"}`, the CA's own error included. Behind NAT, adds `nat` (`direct`: the router holds the public address; `layered`: a second NAT above it; `cgnat`: carrier-grade NAT, where forwarding cannot work; `unknown`) and, once probed, `ports:{"https","http"}`, each `ok` (this server answered from outside), `taken` (something else answered), `closed` or `unknown`. |
| `PUT /api/domain` `{"domain","adopt","currentPassword","totp"}` | Admin. Moves the server onto a domain of the owner's: lowercase LDH labels, at least two (`400` otherwise). Without `adopt`, the server first resolves the name itself and refuses with `409` (no code) until its `A` records point at the server's public IP, which also spares the CA's failed-order limit, and with `409` when the server has no public IP. `adopt:true` skips that check (behind NAT the record points at the router, not at the server) and needs the step-up, since nothing then shows the name is the server's. A `*.hyperdrop.link` name is refused (`400`): free names are connected through `PUT /api/ddns`. On success the domain is stored and certificate issuance starts in the background → `200`, the `GET` document. There is no route that removes the domain: a server always has one. |

Both `<domain>` and `files.<domain>` need an `A` record; the server orders one certificate covering
both.

### Free names and custom DDNS

A server can hold a free `<name>.hyperdrop.link` address from HyperDrop's names service, or keep
an address of its own current through a **custom DDNS recipe**: HTTPS requests the server sends to
a DNS provider whenever its public IPv4 changes. Both run in the server's address updater.

| Call | Behaviour |
|---|---|
| `GET /api/ddns` | Admin. The free name: `{"configured","name","fqdn"}`, and once connected `lastUpdate` (Unix seconds), `lastIP`, `lastError`. While a connection waits for the owner's approval: `enrollment:{"approvalURL","expiresAt"}` and `lastClaimError`. No credential is ever answered. |
| `PUT /api/ddns` `{"name","replace"}` | Admin. Starts (or retries) connecting a free name: 5 to 32 lowercase letters, digits and hyphens (`400` otherwise). The names service asks the owner to approve the connection in their HyperDrop account → `202` with the `GET` document carrying the `approvalURL`; once approved and the server is reachable, `200` and the server adopts the name. Another free name already held → `409 name-permanent` (`replace:true` disconnects it first). A refusal the names service words itself is relayed with its own JSON body (`code`, `error`, and `retryAfter` or `approvalURL` where they apply) as `503`, or `429` when rate-limited. Otherwise: a name that is taken → `409`; refused → `422`; rate-limited → `429`; the service unreachable → `502`. |
| `DELETE /api/ddns?pendingName=<name>` | Admin. Disconnects this server from its free name and removes its DNS records → `200 {"configured":false}`; the name stays the owner's. `pendingName` cancels only that pending connection. A failure at the names service → `502`, the local credential kept for a retry. The server's current domain is not changed. |
| `GET /.well-known/hyperdrop-names` | No auth, on port 80 and 443. `{"challenge"}` while a connection waits for approval, so the names service can check it reaches this server; `404` otherwise. `Cache-Control: no-store`. |
| `GET /api/connectivity` | Admin. `{"serverID","status","hasCustomConfig","certStatus"}`: the address updater's state (`mode`, `domain`, the recipe's `provider`, `providerZone` and `recipeVersion`, the observed `publicIP`, check and attempt times, the last error, per-host DNS and HTTPS checks, recent events). Never a recipe's requests or secrets. |
| `PUT /api/connectivity` `{"config","currentPassword","totp"}` | Admin, step-up. Replaces the whole custom configuration: `mode` `custom` (the server sends the recipe's requests, 1 to 12 HTTPS requests to literal hosts, with up to 32 secrets of at most 8 KiB each, substituted into them) or `external` (something else keeps DNS current; the server only checks it). Its `domain` must be the server's current domain and not under `hyperdrop.link`. A recipe that asks for `allowPrivate` needs the operator's `HYPERDROP_DDNS_ALLOW_PRIVATE=1`. `provider`, `providerZone` and `recipeVersion` record which tool wrote the recipe; the server stores and echoes them and never acts on them. Any refusal → `400` (no code) naming what is wrong. → the `GET` document. |
| `POST /api/connectivity/check` | Admin. Runs a check now (respecting retry back-off; behind NAT, the reachability probe first), at most 45 seconds → the `GET` document. |
| `GET /api/ddns/available?name=<name>` | Admin. Asks the names service whether a free name is available and relays its JSON answer; a failure → `502`. |

The four connectivity routes answer `503 ddns-unavailable` on a server built without an address
updater. The recipe and the free name's token are kept in `<data>/ddns` (mode 0600) and never
leave the server except in the requests they exist for.

### Other routes

`GET /api/local-addresses`, `GET /api/downloads` and `POST /api/speedtest` are described in
[§ Your account](#your-account), [§ Editing a share](#editing-a-share) and
[§ Upload speed probe](#upload-speed-probe).

## Push notifications

The server can tell a signed-in phone what happened while its app was not running. It never talks
to Apple or Google itself: it seals each notification to the device's own public key and posts
the ciphertext to a **push relay** (`HYPERDROP_PUSH_RELAY`, HyperDrop's relay by default), which
forwards it to the phone's push service without being able to read it. Push is on when
`GET /api/me/push` answers a non-empty `relay`. Delivery is best effort.

### Registering a device

The registration lives on the device's token row, so it goes with the token: signing out,
revoking the token from another device, a password change that signs other devices out and
deleting the account all remove it.

| Call | Behaviour |
|---|---|
| `GET /api/me/push` | *Compressed.* `{"relay","registered","tag","muted"}`. `relay` is `""` when push is off. A registration made with another relay than the server's current one is never used and reads as unregistered. The handle is never answered. |
| `PUT /api/me/push` `{"relay","handle","publicKey","tag","muted"}` | Registers the calling token (a later call replaces it) → `200 {"registered":true}`. `relay` must equal the server's own: the server compares it and never contacts any other relay. `handle` is the relay's handle for this device, 32 lowercase hex characters, and a capability: it is never logged or listed. `publicKey` is the device's X25519 public key, 32 bytes in standard base64. `tag` (up to 64 of `A-Za-z0-9._-`) is opaque to the server and echoed in every message, so the phone knows which account it is about. `muted` lists up to 16 kinds the device takes no push for. Body at most 4 KiB. Push off → `409 push-off`; another relay → `409 relay-mismatch`; a malformed field → `400 invalid` naming it. |
| `DELETE /api/me/push` | Removes the calling token's registration → `204`. |
| `PUT /api/me/activity` `{"onConsole","idleSeconds"}` | A computer reports whether its owner is at it → `204`. `onConsole:true` with `idleSeconds` from 0 to under 300 marks the token in use as of that long ago; anything else clears the mark. Body at most 1 KiB. |

### What is sent

| Kind | When | To |
|---|---|---|
| `inboxReceived` | A sender finished delivering files into one of the account's Receive Inboxes: none of their uploads still in flight and 3 seconds of quiet. Never for an inbox with `notify:false`, and never for files the owner's `seenAt` already covers. | The inbox's owner |
| `accessRevoked` | An administrator took away a server folder one of the account's linked shares served. | That account |
| `domain` | The server's free name broke (unauthorized, silent or failing) or recovered. | Every administrator |
| `serverUpdate` | A server update reminder came due (a new release, or a failed install). Each reminder once. | Every administrator |
| `deviceSignedIn` | A signed-in phone signed a computer in to the account, at the moment the computer collects its token. Each computer once. | Every registered device of the account except the new computer |

Nothing is pushed for an account while one of its computers is in use: a token whose
`X-HyperDrop-Client` platform is `macos`, `windows` or `linux` marked activity within the last 5
minutes. That computer announces instead, and what was skipped is not pushed later. The one
exception is `deviceSignedIn`, which is sent whatever any computer's activity, so a computer
signed in by someone else cannot silence the notice about itself, and which no device can mute
(`muted` refuses it). A suspended or
expired account is not pushed to. A device's muted kinds are never sent to it. The first
evaluation for an account only records what exists, so a newly registered phone is not told about
last month; a server back from a long absence (about seven minutes without its heartbeat, as when a
previous release ran meanwhile) records everything and pushes nothing. Each announcement is
recorded before it is sent and sent only once the record is durable, so a crash loses a
notification rather than repeating it.

### The message

The plaintext is JSON:

```json
{"v":1,"kind":"inboxReceived","title":"Contracts","body":"Received 3 files",
 "thread":"inbox-4Gt8sQx2Lm","tag":"…","unseen":5,"ref":"4Gt8sQx2Lm"}
```

`thread` groups notifications (`inbox-<id>`, `revoked`, `domain`, `server-update`,
`device-signed-in`); `unseen` is the account's unseen inbox files now (on an inbox delivery; `0`
otherwise); `ref` is the inbox or share a tap opens. A `deviceSignedIn` message also carries the
computer's `tokenId` (the token its Sign Out action revokes), `label`, `platform`, `approvedBy`,
`username` and `at` (RFC 3339); no other kind carries those keys. Its title is "A computer
signed in" and its body `"<label>" (<system>) signed in to <username>, approved by <approving
device>. If this wasn't you, sign it out.` The plaintext is at most 2,800 bytes (the body is cut
first, then the title). It is
sealed with HPKE in base mode (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305, info
`HyperDrop push v1`; `core/pushseal`) to the registration's public key.

The server sends `POST <relay>/v1/push/send` with
`{"handle","ciphertext","collapseId"}`: `ciphertext` is standard base64 of `enc || ciphertext`,
and `collapseId` lets the phone's push service replace an older notification of the same thing
(`in-<24 hex>`, a SHA-256 of the inbox id, the sender and the first file, so the inbox's id, its
anonymous upload link, never travels in the clear; `rv-<time>`; `dm-<state>`; `su-<key>`;
`si-<24 hex>`, a SHA-256 of the computer's token id). A send
has 10 seconds and follows no redirect. A `410` from the relay removes that handle from its token
row; any other failure keeps the registration and loses that one notification, logged with the
kind, the account and the relay's status, never the handle or the ciphertext.

**What the relay learns:** the handle (which device), the collapse id, the ciphertext's length,
when it was sent, and the sending server's address and version (`User-Agent: hyperdrop-server/<version>`). **What it never gets:** the plaintext (the title, the body, file names, the
inbox or share id), the account's name or the server's tokens.

## Public routes

The public routes take no account: the share's id (10 base58 characters) and each file's UUIDv4
slug are the capability, and URLs never carry a file's name. Nothing distinguishes a share that
never existed from one that expired, was deleted, belongs to a suspended account, or is a Receive
Inbox: each is the same `404`.

### Two origins

Uploaded bytes are served only from `files.<domain>`; the server's own pages only from
`<domain>`.

| Origin | Routes |
|---|---|
| `files.<domain>` | `/view/…`, `/download/…`, `/zip/…`, `/site/…`, `/thumb/…`, `/access/…` |
| `<domain>` | `/share/{id}`, `/unlock/{id}`, `/receive/…`, `/`, `/join` and `/app…` |
| any host | `/api/…`, `/share/{id}/status`, `/card…`, `/favicon.ico`, `/icon.svg`, `/.well-known/hyperdrop-names`, and the not-found page |

A `GET` or `HEAD` on the wrong host (including the bare IP address) is answered `308` to the same
path on the right one; any other method gets a plain `404`. Links may therefore name either host:
a payload link on `<domain>` costs its recipient one `308`.

This split is a browser trust boundary, not tidiness. `/view` serves an uploaded `.html` or `.svg`
inline as a live page. On the page origin its script would be first-party: able to ride the access
cookies of every share the visitor has unlocked, and to draw a copy of the password form under the
real domain and certificate. No response header fixes that; a second origin does. An IP address or
a second port cannot be split that way, which is why a server requires a domain. The status poll
answers on both origins because the waiting page renders on the file origin and polls it with a
relative `fetch()`, which cannot follow a `308` across origins. Without a domain (development mode)
both origins are one, and the boundary is not there to test.

**Uploaded documents run sandboxed.** A file a browser would render as a document (`text/html`,
`application/xhtml+xml`, `image/svg+xml`, `text/xml`, `application/xml`, `text/xsl`, any `+xml`
type, and any type that does not parse) is served on `/view`, `/download` and `/site` with
`Content-Security-Policy: sandbox allow-scripts allow-forms allow-popups allow-modals
allow-downloads`. The page renders and runs its own script, in an opaque origin: it cannot read
another file of the file origin, through a frame, a canvas or a credentialed fetch. The sandbox never
includes `allow-same-origin` or `allow-popups-to-escape-sandbox`. In practice a shared website's
relative stylesheets, images, classic scripts and links between pages work; `fetch()` of its own
files, module scripts, local `@font-face` and `localStorage` do not.

**The server's own pages carry a page policy:** `Content-Security-Policy: base-uri 'none';
object-src 'none'; form-action 'self' https://<domain> https://files.<domain>` (`form-action
'self'` alone without a domain). It refuses only what none of these pages does: a `<base>`, plugin
content, and a form posting anywhere else. The password form, `/` and `/join` also refuse every
frame (`frame-ancestors 'none'` and `X-Frame-Options: DENY`), since a framed password form is what
clickjacking wants; the listing, the gallery and the Receive Inbox page can be embedded. Every
page, every payload response, the tiles and the poster carry `X-Robots-Tag: noindex`.

### The routes

| Route | Behaviour |
|---|---|
| `GET /share/{id}` | The View link. In order: the access gate (below); a link unfurler gets a preview card; while any file is still uploading, the whole-share waiting page; a gallery (`media`) renders the gallery; a share with an `entry` that resolves → `302` to `/site/{id}/<entry>`; a share of one file without `listing` → `302` to `/view/{id}/{slug}`; otherwise the listing of the share's root, or of one folder with `?dir=<relpath>` (an unknown folder → `404`). `?files=1` renders the listing whatever the share opens as. The listing names files as they were shared; its links use slugs and `/site` paths, and offers "Download all (.zip)" and, inside a folder, that folder's zip. *Compressed.* |
| `GET /view/{id}/{path...}` | `{path...}` is the file's slug. The file inline (`Content-Disposition: inline; filename=…`), its type from the name with a sniffing fallback. A file a browser does not render inline is served as an attachment instead, so a hand-built View link degrades into a download. Ranges and resumption (`Accept-Ranges: bytes`, `206`, `If-Range` against the ETag or the date); the ETag is the file's SHA-256. Text-like types negotiate `zstd` or `gzip` when the request has no `Range` (the ETag then gains a `-zstd`/`-gzip` suffix and `Content-Length` goes); PDFs, media and archives are never encoded. An inbox's file → `404`, even with a bearer. |
| `GET /download/{id}/{path...}` | `{path...}` is the file's slug. The same file as an attachment, byte for byte, with ranges; never content-encoded. Also accepts `Authorization: Bearer` with the **owner's** token, which passes the password gate (and is the one read of an inbox's files): the owner's own client can read bytes it has no password for. No cookie is set then. Here, on `/view` and on `/site`, a reader that takes no bytes for 60 seconds is dropped. |
| `GET /zip/{id}?dir=<relpath>` | The share (or one folder of it, entries rebased onto that folder) as a zip built on the fly, store method, named after the share or the folder. Not resumable. Carries an exact `Content-Length` unless the archive needs zip64 records (a file or the total past 4 GiB, or 65,535 entries) or the share has a linked source; then it streams without one. At most 2 zips stream at once on the server (1 per share owner, and 1 per client address, an IPv6 address by its /64; others wait their turn), a stream whose reader stops taking bytes for 60 seconds is dropped, and so is one read at less than 16 KiB/s on average over 30 seconds. While any file is pending, the waiting page instead. An unknown folder → `404`. |
| `GET /site/{id}/{path...}` | A file of the share by its **relative path** rather than its slug, so a folder of HTML works as a website: a page at `/view/{id}/{slug}` would resolve `href="style.css"` to nothing. Served exactly like `/view` (sandbox included). A directory serves its `index.html`, and a directory path without the trailing slash is `301`'d to it so relative links resolve. A path the share does not hold is `404`, which is also the traversal defence: matching is against the share's own list, so nothing else is addressable however it is spelled. A path that a chat client re-encoded (`%2524` for `%24`) is `301`'d to its canonical form. While a website's files are still uploading, the waiting page. |
| `GET /site/{id}` | `301` to `/site/{id}/`. |
| `GET /thumb/{id}/{slug}` | One gallery tile (`image/jpeg`). Gated like `/view`: a protected share asks for its password, and the tile is then `Cache-Control: private`. No tile → `404`. |
| `GET /share/{id}/status` | Upload progress for the waiting page: see [§ Early links](#early-links). |
| `POST /unlock/{id}` | The password form's target. Form fields `password` and `next` (where to go afterwards: an address of this share's own public routes, with no scheme, host, backslash, dot segment or control character, else `/share/{id}`, or `/receive/{id}` for an inbox). A correct password sets the access cookie and `303`s to `next` (through `GET /access/{id}` when the server has a domain, below); a wrong one renders the form again with `401`. A share with no password → `404`; a body over 64 KiB or not a form → `400`. |
| `GET /access/{id}?token=<t>&next=<address>` | The access hop, on `files.<domain>`, for browsers only. A correct password on the page origin (`POST /unlock/{id}`, or `?pw=` on a top-level navigation there) sets that origin's access cookie and `303`s here with a one-minute `token`; this route sets the files origin's own access cookie and `303`s onward to `next`, relative for a files-origin address and `https://<domain>…` for a page. A token for another share, expired, tampered, issued under an older password, or an access cookie or site grant value sets nothing, and the `303` then reaches the password form. `next` passes the same filter as `/unlock`'s, else `/share/{id}`. `Cache-Control: no-store`, `Referrer-Policy: no-referrer`. A Receive Inbox → `404`; a linked share with a revoked source → the unavailable page. Without a domain there is no hop. |
| `GET /access/clear` | On `files.<domain>`: the files-origin half of a web sign-out, at the `accessClear` address `DELETE /api/web/session` answered. It clears only for that sign-out's pair: `t`, `<expiry>.<hex HMAC-SHA256>` over `access-clear|<nonce>|<expiry>|0`, valid one minute, and the `hd_clear` cookie holding that nonce (16 random bytes per sign-out). With the pair it clears every access cookie (`hd_<share id>`) the request carries there, with the attributes the hop set, and `hd_clear`; without it (no token, an expired, tampered or other-scope token, no cookie, another sign-out's token or cookie) it clears nothing. Either way a 1×1 `image/gif`, `Cache-Control: no-store`; it reads no share. A cross-site page cannot trigger the clear: anyone can get a token by signing out, but not put the nonce cookie in the visitor's browser. A host under the same registrable domain that can set cookies there can force it: another `*.hyperdrop.link` server (that zone is not a public suffix) can mint a pair through this server's sign-out, set `hd_clear` with `Domain=hyperdrop.link` and load the clear. The cost is only that the visitor unlocks the share again; the clear opens nothing. |
| `GET /receive/{id}`, `PUT /receive/{id}/files/{name}` | A Receive Inbox's upload page and its anonymous upload: [§ Receive Inboxes](#receive-inboxes). |
| `GET /card.png`, `GET /card-video.png` | The static preview images (1200×630): the brand card and a play tile. |
| `GET /card/{id}/poster.jpg` | The share's poster frame for link previews. Never for a password-protected share, a share whose poster's entry was deleted or hidden, or one with a revoked source (`404`). |
| `GET /favicon.ico`, `GET /icon.svg` | The tab icon every page links: static, `Cache-Control: public, max-age=604800`, with an ETag. |
| `GET /{$}` (the bare `/`) and `GET /join` | The server's front page: a sentence saying files on this server are shared through the HyperDrop apps, with a link to them; `/join` also names the server's address and offers to open it in the app. An invite link is `/join#<code>`: the code rides in the URL fragment, which the browser never sends to the server, and the page's own script shows the sign-in it carries only when the code names this same server. Both link `/app/` ("Use HyperDrop in this browser") while it serves the [web client](#the-web-client). `no-store`, never framed. |
| `GET /app`, `GET /app/{path...}` | The [web client](#the-web-client). |
| `GET /` | Any other path: a not-found page (`404`). |

A request for an unknown share or file on the page and payload routes gets that not-found page;
the image routes, the status poll and the inbox upload answer a plain `404`.

### The access gate

Every public read of a share passes the same gate:

- **No password**: served.
- **Password**: the request needs one of
  - a valid **access cookie** `hd_<id>` (below);
  - `?pw=<password>`, for clients without cookies: a match also sets the cookie, and a browser's
    top-level navigation is answered `303` to the same address without `pw`, so the password leaves
    the address bar and history;
  - otherwise the server answers the share's own address with a self-contained **password form**
    (`200`; nothing of the file, listing or zip is sent) that posts to `POST /unlock/{id}`.
- Every response a protected share admits carries `Cache-Control: private` (or something
  stricter), so no shared cache answers the next visitor.

**Share-password guessing** is counted per client address (an IPv6 address by its /64) and share,
across both `POST /unlock/{id}` and `?pw=` (a Receive Inbox's page included): 10 wrong guesses at
one share within an hour block that address from that share's password check for 1 hour, every
attempt meanwhile answered with a `429` page; a block that starts while the previous one is
remembered (for as long after its end as it lasted) lasts twice that one, up to 12 hours. The
address's other shares are unaffected, and a correct password forgets the address's guesses at that
share. Only a first-party guess counts on the address: no Fetch Metadata (the apps, curl, and
every browser on plain HTTP, which sends it only to HTTPS and localhost), or a top-level document
(`Sec-Fetch-Dest` absent or `document`) whose `Sec-Fetch-Site` is `none` (it stays `none` across
the redirect between the two origins), `same-origin`, or `same-site` with an `Origin` naming one of
the server's two hosts (a same-site request with no `Origin` does not count). A guess another
website makes the browser send (an `<img>`, a frame, a sandboxed `/site` page's fetch, a cross-site
navigation or form) is checked all the same and counts on the share's lane alone. Each share also has a lane: after ten
wrong guesses at it from any addresses, it admits one guess per 30 seconds, and the rest get the
`429` page ("Password entry for this share is paused."; an address block reads "Password entry from
your address is paused."), an HTML page with no `code` and no `Retry-After` header. An hour without a
failure resets the lane, and a correct password keeps its count. The counter is in memory; existing
access cookies keep working during a block.

**The access cookie** is `hd_<id>`, valued `<expiry Unix seconds>.<hex HMAC-SHA256>` over
`<id>|<expiry>|<password generation>`, keyed by the volume secret. `HttpOnly`, `SameSite=Lax`,
`Secure` under TLS or whenever a domain is set, `Path=/`, about 12 hours, and no `Domain`: it is
host-only on the origin that set it, so no other host under the domain (a `www`, a blog, a CNAME to
another service on an apex domain) ever receives it. The page origin sets its copy on a correct
password and hands the files origin its own through `GET /access/{id}`; `?pw=` answered on the files
origin sets that origin's copy alone. It opens only the share it was issued for. The hop's token is
`<expiry>.<hex HMAC-SHA256>` over `access-hop|<id>|<expiry>|<password generation>`, valid one minute. The password generation moves on
every password change or removal, so cookies issued under an old password stop working at once.

**Which requests the cookie is honoured for.** Every upload is served from the one file origin,
so script in an uploaded page is same-origin with every other share's bytes, and the visitor's
cookies ride along on what it loads. On the file origin the cookie is therefore honoured only for
requests a person makes: no `Sec-Fetch-*` headers at all (curl, apps, older browsers),
`Sec-Fetch-Dest: document`, the media and plugin destinations (`image`, `video`, `audio`, `track`,
`embed`, `object`), and `Sec-Fetch-Dest: empty` with `Sec-Fetch-Mode: navigate` (what "Save link
as" sends), plus a `same-origin` `fetch()` of the status poll. Every other destination (frames,
scripts, styles, fonts, workers) and every other `fetch()` or XHR gets the password form instead.
On the app origin every request shape is honoured: nothing uploaded is ever served there.

**Protected websites.** A protected share's pages stay on their copyable `/site/{id}/{path}`
address (a visitor without the cookie gets the password form). Their stylesheets, scripts, fonts
and pictures arrive from the sandbox's opaque origin with no cookie and no `Referer`, so an
admitted page is `302`'d to `/site/{id}/<grant>/{path}`: the grant has the cookie's shape, signed
over its own message (so neither is accepted as the other), bound to the share and its password
generation, and valid 12 hours. A grant admits only subresource requests, and only for files that
are not documents (HTML, XHTML and XML go through the cookie gate even under a grant; SVG is a
picture); granted responses carry `Referrer-Policy: no-referrer`. A leaked granted address
therefore reaches the share's non-page files until it expires, never a page, the listing, `/view`,
`/download` or `/zip`. A password change revokes every grant with every cookie.

**Accounts that refuse embedding.** When the share owner's account has `noEmbed`, `/view`,
`/download` and `/site` answer with `Cross-Origin-Resource-Policy: same-origin` (`same-site` for
this server's own gallery page), and a request announcing itself as another site's embed
(`Sec-Fetch-Site: cross-site` with an image, media, frame or object destination) is answered `302`
to `/share/{id}` instead of the content. Direct opens, links from other sites and non-browser
clients are unaffected. A share that opens as a website is exempt on `/site`, since its pages run in
an opaque origin whose own assets look cross-site.

### Who visited

Every share counts its distinct visitors (`visitors` in the share view). The unit is a browser:
the share page, `/site/{id}`, the Receive Inbox page and the password form set `hd_visitor`, 16
random bytes as base64url, `HttpOnly`, `SameSite=Lax`, `Secure` under TLS, `Path=/`,
`Domain=<domain>`, for a year. It names the domain so a page view and the files-origin request it
leads to count as one visitor; it grants nothing, so a sibling host that receives it learns only a
random value. A request without a cookie of that shape counts once per address and
`User-Agent`. The rows hold `HMAC(volume secret, "cookie", token)` or `HMAC(volume secret, "ipua",
address, User-Agent)`, never the token or the address. Counted: a successful read of the share
page, `/view`, `/download`, `/site`, `/zip` and the inbox page. Not counted: the owner's own bearer
reads, an unfurler's card, a refusal, the waiting page, tiles, and a live share whose sharer is
offline. At most 100,000 visitors are recorded per share. Visits are written every 15 seconds and
at shutdown, without moving `modifiedAt`. The cookie carries **no authority**: no gate reads it.

### Link previews

When a pasted link is fetched by a known link unfurler (matched on its `User-Agent`: Telegram,
Slack, Discord, Facebook, Twitter, WhatsApp, LinkedIn, Skype, Apple, Signal, Mastodon, Bluesky,
Reddit, Pinterest, Iframely, Embedly and a few more), `/view`, `/download`, `/zip`, `/site` and
`/share` answer a small HTML page of Open Graph tags instead of the content, which also keeps a bot
from costing a full transfer. The card is metadata only, after the access gate:

| Share | Title | Description |
|---|---|---|
| One file | the file name | `PDF · 2.4 MB · Shared via HyperDrop` (an MP4 adds its duration from the container header) |
| Several files | the share's name, else `12 files` | `12 files · 340 MB · Shared via HyperDrop` |
| Password-protected | `Password-protected` | `Shared via HyperDrop` |
| Receive Inbox | its name | its note |
| Password-protected Receive Inbox | `Password-protected` | `Shared via HyperDrop` |

`og:image` is the brand card, the play tile for a share holding video, or the owner's poster frame
(`/card/{id}/poster.jpg`), never a frame for a protected share. A Receive Inbox, protected or not,
always carries the brand card and its `/receive/{id}` address, so its card says nothing about
what it has received. `og:url` is built from the server's
domain (or its IP address), not from the request's `Host` (which is used only when the server has
neither, in development mode).

**Playable video cards.** A single MP4 that has committed, is at most 20 MiB, belongs to an
unprotected stored share and is not a linked entry also gets `og:video` (its `/view` URL with
`?ogmedia=1`, so the unfurler's fetch with the same `User-Agent` gets the file instead of the card),
its type and its dimensions, and plays inside the chat message. The unfurler downloads the clip
and keeps a copy on its own infrastructure, which outlives deleting the share: this is the one
place a preview carries content rather than metadata.

## Error codes

Every `code` the server answers. A refusal without a code is identified by its status alone. The
same store condition answers with the same status and code on every route that meets it.

| Code | Status | Meaning |
|---|---|---|
| `account-disabled` | 403 | The account is suspended or past its expiry. The one `403` a client should treat as permanent for that account. |
| `arch-mismatch` | 400 | `POST /api/server/update`: the build is for another architecture. |
| `backup-failed` | 500 | `POST /api/server/update`: the database backup taken before an update failed; nothing was staged. |
| `bad-body` | 400 | An upload body that arrived whole and does not decode: a corrupt `zstd` stream, one that ends inside a frame, or a batch's tar stream that ends inside an entry. |
| `bad-credentials` | 401 | Sign-in: wrong username or password (one answer for both). |
| `bad-name` | 400 | A username outside 3-32 of `a-z 0-9 . _ -`. |
| `bad-request` | 400 | `GET /api/admin/log` or `GET /api/downloads` parameters out of range. |
| `bad-role` | 400 | A role other than `admin` or `user`. |
| `bad-signature` | 400 | `POST /api/server/update`: the signature is not base64 or does not verify for this binary, architecture and version. |
| `bad-source` | 400 | A linked-share path that is malformed or hidden, two sources with one name, `source` and `sources` together, or a folder where a file is wanted. |
| `body-incomplete` | 408 | An upload body that stopped arriving: it stalled past the server's limits, or its connection ended before it was whole. |
| `body-too-large` | 413 | The request body passes the route's cap. |
| `client-outdated` | 409 | The client named in `X-HyperDrop-Client` is too old for this server. |
| `client-required` | 400 | A request of the computer sign-in by phone (any of its five routes) without an `X-HyperDrop-Client` header naming a version and a system. |
| `closed` | 403 | Upload into a Receive Inbox that is closed. |
| `conflict` | 409 | A write lost a race with another (the inbox closed while the upload ran, say). |
| `ddns-unavailable` | 503 | The server runs no address updater, so the connectivity routes do not exist on it. |
| `desktop-sign-in-admin` | 403 | A computer's sign-in by phone for an administrator's account, refused at the claim and at the mint. |
| `desktop-sign-in-expired` | 410 | A computer's sign-in request that is unknown, lapsed, burned, denied, spent or another account's: the computer asks for a new code. |
| `desktop-sign-in-limit` | 429 | The approving device already signed in 3 computers in the last 24 hours. |
| `desktop-sign-in-off` | 403 | An administrator turned signing computers in by phone off on this server. |
| `desktop-sign-in-refused` | 403 | A computer's sign-in request from a browser or the web client, or an approval (of a computer, a browser or a device link) by a device a phone signed in. |
| `device-link-invalid` | 404 | A device link that is unknown, expired, burned, spent, another device's, or in the wrong state. |
| `device-link-wrong-number` | 409 | The approving number does not match the phone's; the link is burned. |
| `device-too-new` | 403 | A token younger than 24 hours tried to sign another device out or mint a device link. |
| `into-itself` | 400 | A move into the moved folder itself. |
| `invalid` | 400 | `PUT /api/me/push` or `PATCH /api/server/settings`: a field is malformed (the message names it). |
| `invite-invalid` | 404 | An invite that is unknown, spent or expired. |
| `invite-needs-code` | 403 | An invite for an account with a second factor: sign in with the password and a code. |
| `last-admin` | 409 | The change would leave the server without an active, or a never-expiring, administrator. |
| `linked-filter-too-big` | 413 | A linked share's filters would hold more than 20,000 paths. |
| `live-share-ended` | 404 | Resuming a live share that ended or is not the caller's. |
| `live-share-resume-mismatch` | 409 | Resuming a live share with a manifest that differs. |
| `locked-out` | 429 | Too many wrong passwords or codes from this address, or a wait on an account's lane; `Retry-After` says when to try again. |
| `manifest-too-big` | 413 | A creation manifest over 10,000 files (100,000 for a live share). |
| `name-permanent` | 409 | `PUT /api/ddns`: another free name is connected; disconnect it first or send `replace`. |
| `no-pictures` | 400 | `media:true` on a share with nothing a gallery shows. |
| `no-space` | 507 | The write would dip into the server's free-disk reserve, or the disk is full. |
| `not-a-server-binary` | 400 | `POST /api/server/update`: the body is not a Linux executable. |
| `not-a-source` | 400 | A `linked` edit names a source the share does not have. |
| `not-empty` | 409 | Deleting a folder that still holds files. |
| `not-found` | 404 | The share (or the file, folder, token, tile or poster the route names) does not exist for this account. To a client mid-upload, the share was deleted or expired meanwhile. |
| `not-gallery-playable` | 400 | `media:true` on a share holding a file browsers cannot play. |
| `not-text-share` | 409 | `GET /api/shares/{id}/text` on a share that is not a text share. |
| `password-too-long` | 400 | A chosen password or a share password over 72 bytes. |
| `password-too-short` | 400 | A chosen password under 8 bytes. |
| `path-taken` | 400 | A file or folder already stands at the destination, or a linked source lists that name. |
| `push-off` | 409 | Push notifications are off on this server. |
| `quota` | 507 | The write would pass the owner's storage quota. |
| `quota-required` | 400 | Creating a `user` account without `quotaBytes`. |
| `rate-limited` | 429 | The share-creation rate limit, or no free slot for an anonymous inbox upload; `Retry-After` says when. |
| `receive` | 409 | A Receive Inbox's files cannot be moved and it holds no folders. |
| `receive-full` | 413 | A Receive Inbox's byte or file cap is reached, or a name was taken too many times. |
| `relay-mismatch` | 409 | A push registration names another relay than the server's. |
| `revokes-shares` | 409 | The account edit would revoke linked shares; the body lists them under `shares`. Send again with `confirmRevoke`. |
| `self-target` | 403 | An administrator aimed a demotion, suspension, expiry or deletion at their own account. |
| `self-update-unavailable` | 409 | This server cannot install updates on its own, so the switch does not apply. |
| `server-outdated` | 409 | The client named in `X-HyperDrop-Client` is too new for this server: an administrator updates it. |
| `share-incomplete` | 409, 400 | Moving a file that is still uploading (`409`); `media:true` while files are uploading (`400`). |
| `share-linked` | 409 | Deleting or moving an entry a linked source serves. |
| `source-exclusive` | 400 | A linked source on a Receive Inbox. |
| `source-forbidden` | 403 | A linked-share path outside what the caller may share; `?all=1` from a non-administrator. |
| `file-pending` | 409 | A download ticket, or a text share's text, asked for a file that is still uploading. |
| `source-missing` | 404 | A linked-share path that resolves to nothing, or the owner's download of a share whose source cannot be read. |
| `source-revoked` | 409 | Fixing a source the owner's access no longer covers. |
| `source-too-big-to-fix` | 400 | Fixing a source whose walk passes 10,000 entries. |
| `speedtest-busy` | 429 | Another upload probe is running. |
| `step-up-required` | 403 | The call needs the caller's current password (and code). |
| `text-share` | 409 | A text share takes no second file, delete, folder, move, page, gallery, listing or server folder. |
| `text-not-utf8` | 409 | `GET /api/shares/{id}/text`: the text share's file is not UTF-8. |
| `text-too-large` | 413 | `GET /api/shares/{id}/text`: the text share's file is over 256 KiB. |
| `thumb-too-large` | 413 | A gallery tile over 512 KiB. |
| `too-many-devices` | 409 | A computer's sign-in by phone for an account signed in on as many devices as it may be; no device is signed out to make room. |
| `too-many-folders` | 400 | A share already holds 1,000 folder records. |
| `too-many-live-shares` | 429 | The account already runs 3 live shares. |
| `too-many-tickets` | 429 | `POST /api/shares/{id}/download-ticket`: the account holds 64 live download tickets, or the server 4,096; `Retry-After: 5`. |
| `too-many-watchers` | 429 | Too many parked watch requests for the account or the server; `Retry-After: 5`. |
| `totp-already-on` | 409 | Starting an enrolment while a second factor is confirmed. |
| `totp-invalid` | 401 | A wrong, replayed or unknown code. |
| `totp-not-pending` | 409 | Confirming with no enrolment started. |
| `totp-off` | 409 | New recovery codes for an account with no second factor. |
| `totp-required` | 401 | The password was right and the account has a second factor: ask for a code and call again. |
| `totp-self-reset` | 403 | An administrator aimed the second-factor reset at their own account. |
| `totp-setup-required` | 403 | `POST /api/server/update` needs the caller to have a second factor. |
| `unsigned-binary` | 400 | `POST /api/server/update` without a signature. |
| `update-failed` | 502 | `POST /api/server/update/latest`: the release manifest or the newest release could not be fetched or did not verify; the server log has the cause. |
| `update-in-progress` | 409 | `POST /api/server/update/latest`: a release is already staged and waiting for the installer. |
| `update-unsupported` | 501 | This install cannot be updated over the API (no root updater), or cannot install a release itself (`POST /api/server/update/latest`): update it the way it was installed. |
| `use-change-password` | 403 | A web session set its own account's password through `PATCH /api/users/{name}`: use `PATCH /api/me/password`. |
| `user-exists` | 409 | The username is taken. |
| `user-has-shares` | 409 | The account still owns a share after the delete pass. |
| `user-not-found` | 404 | No such account. |
| `web-bundle-invalid` | 400 | `PUT /api/server/web`: the signature does not verify for the version, build and contract named, a parameter is malformed, or the archive is not a web bundle. |
| `web-bundle-outside-window` | 409 | `PUT /api/server/web`: the bundle speaks a contract this server does not serve. |
| `web-elevation-required` | 403 | An admin write from a web session that is not elevated: `POST /api/web/session/elevate`, then send it again. |
| `web-off` | 403 | The web client is turned off on this server. |
| `web-session-only` | 400 | A web session route called with a bearer token. |
| `web-session-refused` | 403, 401 | A web sign-in or phone sign-in request from another host or origin, or without the web client header (`403`); a web session on a route that does not take one (`401`). |
| `web-sign-in-expired` | 410 | A phone sign-in request that is unknown, lapsed, burned, denied, spent or another device's: the browser asks for a new code. |
| `web-unavailable` | 503 | The web client is not served here: no bundle is installed, or the installed one speaks a contract this server no longer serves (a web session route), or the server has no place to install one (`PUT /api/server/web`). |
| `wrong-password` | 401 | The current password given for a step-up is wrong. |

`PUT /api/ddns` relays the names service's own refusals (`503`, or `429` when rate-limited) with
the codes that service defines.

## Route index

Every route the server registers, exactly as registered. `{path...}` is the rest of the path: a
relpath, or a file's slug on `/view` and `/download`. *token*: any signed-in account; *admin*: an
administrator.

| Route | Auth | Section |
|---|---|---|
| `GET /api/health` | none | [Server administration](#health) |
| `GET /.well-known/hyperdrop-names` | none | [Free names and custom DDNS](#free-names-and-custom-ddns) |
| `POST /api/auth/login` | none | [Signing in](#signing-in) |
| `POST /api/auth/invite` | none | [Signing in](#signing-in) |
| `POST /api/auth/device-link/claim` | none | [Signing in a phone](#signing-in-a-phone-from-a-signed-in-device) |
| `POST /api/auth/device-link/poll` | none | [Signing in a phone](#signing-in-a-phone-from-a-signed-in-device) |
| `DELETE /api/auth/token` | token | [Signing in](#signing-in) |
| `POST /api/web/session` | none | [Web sessions](#web-sessions) |
| `GET /api/web/session` | web session | [Web sessions](#web-sessions) |
| `DELETE /api/web/session` | web session | [Web sessions](#web-sessions) |
| `POST /api/web/session/elevate` | web session | [Web sessions](#web-sessions) |
| `POST /api/web/phone-sign-in` | none | [Signing a browser in with a phone](#signing-a-browser-in-with-a-phone) |
| `POST /api/web/phone-sign-in/poll` | none | [Signing a browser in with a phone](#signing-a-browser-in-with-a-phone) |
| `POST /api/me/web-sign-ins/claim` | token | [Signing a browser in with a phone](#signing-a-browser-in-with-a-phone) |
| `POST /api/me/web-sign-ins/{id}/approve` | token | [Signing a browser in with a phone](#signing-a-browser-in-with-a-phone) |
| `POST /api/me/web-sign-ins/{id}/deny` | token | [Signing a browser in with a phone](#signing-a-browser-in-with-a-phone) |
| `POST /api/auth/desktop-sign-in` | none | [Signing a computer in with a phone](#signing-a-computer-in-with-a-phone) |
| `POST /api/auth/desktop-sign-in/poll` | none | [Signing a computer in with a phone](#signing-a-computer-in-with-a-phone) |
| `POST /api/me/desktop-sign-ins/claim` | token | [Signing a computer in with a phone](#signing-a-computer-in-with-a-phone) |
| `POST /api/me/desktop-sign-ins/{id}/approve` | token | [Signing a computer in with a phone](#signing-a-computer-in-with-a-phone) |
| `POST /api/me/desktop-sign-ins/{id}/deny` | token | [Signing a computer in with a phone](#signing-a-computer-in-with-a-phone) |
| `GET /api/me` | token | [Your account](#your-account) |
| `GET /api/local-addresses` | token | [Your account](#your-account) |
| `GET /api/me/tokens` | token | [Your account](#your-account) |
| `DELETE /api/me/tokens/{id}` | token | [Your account](#your-account) |
| `POST /api/me/device-links` | token | [Signing in a phone](#signing-in-a-phone-from-a-signed-in-device) |
| `GET /api/me/device-links/{id}` | token | [Signing in a phone](#signing-in-a-phone-from-a-signed-in-device) |
| `POST /api/me/device-links/{id}/renew` | token | [Signing in a phone](#signing-in-a-phone-from-a-signed-in-device) |
| `POST /api/me/device-links/{id}/approve` | token | [Signing in a phone](#signing-in-a-phone-from-a-signed-in-device) |
| `POST /api/me/device-links/{id}/deny` | token | [Signing in a phone](#signing-in-a-phone-from-a-signed-in-device) |
| `PATCH /api/me/password` | token | [Your account](#your-account) |
| `GET /api/me/push` | token | [Push notifications](#registering-a-device) |
| `PUT /api/me/push` | token | [Push notifications](#registering-a-device) |
| `DELETE /api/me/push` | token | [Push notifications](#registering-a-device) |
| `PUT /api/me/activity` | token | [Push notifications](#registering-a-device) |
| `GET /api/me/totp` | token | [Two-factor authentication](#two-factor-authentication) |
| `POST /api/me/totp` | token | [Two-factor authentication](#two-factor-authentication) |
| `POST /api/me/totp/confirm` | token | [Two-factor authentication](#two-factor-authentication) |
| `DELETE /api/me/totp` | token | [Two-factor authentication](#two-factor-authentication) |
| `POST /api/me/totp/recovery` | token | [Two-factor authentication](#two-factor-authentication) |
| `DELETE /api/users/{name}/totp` | admin | [Two-factor authentication](#two-factor-authentication) |
| `POST /api/server/update` | admin | [Updating the server](#updating-the-server) |
| `GET /api/server/settings` | admin | [Updating the server](#updating-the-server) |
| `PATCH /api/server/settings` | admin | [Updating the server](#updating-the-server) |
| `PUT /api/server/web` | admin | [The web client](#the-web-client) |
| `POST /api/shares` | token | [Creating a share](#creating-a-share) |
| `GET /api/shares` | token | [Listing shares](#listing-shares) |
| `GET /api/shares/watch` | token | [Watching for changes](#watching-for-changes) |
| `GET /api/shares/changes` | token | [Watching for changes](#watching-for-changes) |
| `POST /api/shares/delete` | token | [Editing a share](#editing-a-share) |
| `POST /api/shares/edit` | token | [Editing a share](#editing-a-share) |
| `GET /api/shares/{id}` | token | [Reading one share](#reading-one-share) |
| `GET /api/sources` | token | [Linked shares](#browsing-the-servers-folders) |
| `GET /api/sources/browse` | token | [Linked shares](#browsing-the-servers-folders) |
| `GET /api/sources/file` | token | [Linked shares](#browsing-the-servers-folders) |
| `PUT /api/shares/{id}/files/{path...}` | token | [Uploads](#uploads) |
| `DELETE /api/shares/{id}/files/{path...}` | token | [Files and folders](#files-and-folders-in-a-share) |
| `POST /api/shares/{id}/move` | token | [Files and folders](#files-and-folders-in-a-share) |
| `POST /api/shares/{id}/folders` | token | [Files and folders](#files-and-folders-in-a-share) |
| `DELETE /api/shares/{id}/folders/{path...}` | token | [Files and folders](#files-and-folders-in-a-share) |
| `POST /api/shares/{id}/batch` | token | [Uploads](#uploads) |
| `PUT /api/shares/{id}/poster` | token | [Previews and gallery records](#previews-and-gallery-records) |
| `POST /api/shares/{id}/thumbs` | token | [Previews and gallery records](#previews-and-gallery-records) |
| `PUT /api/shares/{id}/thumbs/{slug}` | token | [Previews and gallery records](#previews-and-gallery-records) |
| `PUT /api/shares/{id}/gallery` | token | [Previews and gallery records](#previews-and-gallery-records) |
| `POST /api/shares/{id}/download-ticket` | token | [Previews and gallery records](#previews-and-gallery-records) |
| `GET /api/downloads` | token | [Editing a share](#editing-a-share) |
| `DELETE /api/shares/{id}/poster` | token | [Previews and gallery records](#previews-and-gallery-records) |
| `GET /api/shares/{id}/poster` | token | [Previews and gallery records](#previews-and-gallery-records) |
| `GET /api/shares/{id}/thumbs/{slug}` | token | [Previews and gallery records](#previews-and-gallery-records) |
| `GET /api/shares/{id}/text` | token | [Text shares](#text-shares) |
| `GET /api/shares/{id}/uploads/{path...}` | token | [Uploads](#uploads) |
| `PUT /api/shares/{id}/preparing/{path...}` | token | [Uploads](#uploads) |
| `PATCH /api/shares/{id}` | token | [Editing a share](#editing-a-share) |
| `DELETE /api/shares/{id}` | token | [Editing a share](#editing-a-share) |
| `POST /api/live-share` | token | [Live shares](#live-shares) |
| `GET /api/live-share/{id}/jobs` | token | [Live shares](#live-shares) |
| `POST /api/live-share/jobs/{job}` | token | [Live shares](#live-shares) |
| `POST /api/live-share/jobs/{job}/error` | token | [Live shares](#live-shares) |
| `PATCH /api/live-share/{id}` | token | [Live shares](#live-shares) |
| `DELETE /api/live-share/{id}` | token | [Live shares](#live-shares) |
| `GET /api/users` | admin | [Accounts (admin)](#accounts-admin) |
| `POST /api/users` | admin | [Accounts (admin)](#accounts-admin) |
| `GET /api/users/{name}` | admin | [Accounts (admin)](#accounts-admin) |
| `PATCH /api/users/{name}` | admin | [Accounts (admin)](#accounts-admin) |
| `DELETE /api/users/{name}` | admin | [Accounts (admin)](#accounts-admin) |
| `GET /api/usage` | admin | [Usage and logs](#usage-and-logs) |
| `GET /api/admin/log` | admin | [Usage and logs](#usage-and-logs) |
| `POST /api/speedtest` | token | [Upload speed probe](#upload-speed-probe) |
| `GET /api/domain` | admin | [The server's domain](#the-servers-domain) |
| `PUT /api/domain` | admin | [The server's domain](#the-servers-domain) |
| `GET /api/ddns` | admin | [Free names and custom DDNS](#free-names-and-custom-ddns) |
| `GET /api/connectivity` | admin | [Free names and custom DDNS](#free-names-and-custom-ddns) |
| `PUT /api/connectivity` | admin | [Free names and custom DDNS](#free-names-and-custom-ddns) |
| `POST /api/connectivity/check` | admin | [Free names and custom DDNS](#free-names-and-custom-ddns) |
| `GET /api/ddns/available` | admin | [Free names and custom DDNS](#free-names-and-custom-ddns) |
| `PUT /api/ddns` | admin | [Free names and custom DDNS](#free-names-and-custom-ddns) |
| `DELETE /api/ddns` | admin | [Free names and custom DDNS](#free-names-and-custom-ddns) |
| `GET /favicon.ico` | none | [Public routes](#the-routes) |
| `GET /icon.svg` | none | [Public routes](#the-routes) |
| `GET /card.png` | none | [Public routes](#the-routes) |
| `GET /card-video.png` | none | [Public routes](#the-routes) |
| `GET /card/{id}/poster.jpg` | none | [Public routes](#the-routes) |
| `GET /share/{id}` | none | [Public routes](#the-routes) |
| `GET /share/{id}/status` | none | [Early links](#early-links) |
| `GET /thumb/{id}/{slug}` | none | [Public routes](#the-routes) |
| `GET /view/{id}/{path...}` | none | [Public routes](#the-routes) |
| `GET /site/{id}` | none | [Public routes](#the-routes) |
| `GET /site/{id}/{path...}` | none | [Public routes](#the-routes) |
| `GET /download/{id}/{path...}` | none | [Public routes](#the-routes) |
| `GET /zip/{id}` | none | [Public routes](#the-routes) |
| `POST /unlock/{id}` | none | [Public routes](#the-routes) |
| `GET /access/{id}` | none | [Public routes](#the-routes) |
| `GET /access/clear` | none | [Public routes](#the-routes) |
| `GET /receive/{id}` | none | [Receive Inboxes](#the-public-upload-page) |
| `PUT /receive/{id}/files/{name}` | none | [Receive Inboxes](#the-public-upload-page) |
| `GET /{$}` | none | [Public routes](#the-routes) |
| `GET /join` | none | [Public routes](#the-routes) |
| `GET /app` | none | [The web client](#the-web-client) |
| `GET /app/{path...}` | none | [The web client](#the-web-client) |
| `GET /` | none | [Public routes](#the-routes) |
