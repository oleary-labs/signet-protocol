
How auth should be handled - particularly from the 'end user' perspective
* an end user is someone who is assumed to have somehow 'logged in' to an application.
  * likely first implementation will assume 'social login' through an oauth provider
* the application can then submit keygen and signing requests on behalf of the user without further interaction with the user.
* the ability of the application to keygen and sign on behalf of a user should be:
  * validated when requests are first made but also validated at ever step of the protocol across all participating nodes
    * this likely requires that whatever credential or 'auth token' is required will also be propagated to all nodes participating in the protocol.
    * it may be possible to only do this once per protocol invocation and then associate the credential with a 'session'.
  * valid only for a bounded period of time.
    * this constraint could be bounded by the 'auth token' or specified by the application or both. 

### Questions to nail down the design

1. Who is the authorizing party — the application or the user? Is the goal "this application is authorized to use this group" (app-level auth), or
   "this specific user is authorized" (user-level auth)? The doc implies both matter but the first implementation might just need app-level.
2. Where does the authorization policy live? On-chain (factory/group contract), off-chain node config, or trusted from the OAuth token itself?
3. Do you want EIP-712 user signatures (Option C), or is OAuth-only sufficient for the first pass?
4. What does "every step" mean in practice? The session approach (validate once at coord, associate with session ID) seems sufficient — or do you
   want the credential re-checked at each GossipSub round?

Implementation specifics:
* Preferred option: Raw OAuth JWT propagated
  * App sends JWT in Authorization header
  * Initiating node validates (signature + expiry + issuer)
  * JWT embedded in coordMsg.AuthToken []byte
    * this will be validated once when the protocol is initiated and then associated with a session.
  * Each participant node validates the JWT independently (needs JWKS from the OAuth provider)
  * Simple, stateless, but requires every node to reach the OAuth provider's JWKS endpoint
    * Nodes will cache provider keys with defined refresh interval
* The on-chain group definition will have a list of trusted OAuth issuers/client IDs
  * Group owners will be able to manage this trust list - i.e. add or subtract
  * Node will detect (through events) when the list changes and adjust dynamically. There should be a defined delay to change the list.
* Standard oauth tokens are scoped by both user and 'application'
  * The application scope should also be defined in the group contract and validated as part of authorization.
  * the user scope of the auth token should be used as the id which identifies the key in the protocol
  * There should be an optional protocol parameter that allows an additional identifier to be appended to the key id. this allows an app to manage multiple keys on behalf of a user if desired.

More Questions

1. JWKS discovery: Use OpenID Discovery ({iss}/.well-known/openid-configuration → jwks_uri) or assume {iss}/.well-known/jwks.json directly?
   Discovery is more correct (especially for Google which uses a different JWKS URL) but adds an extra HTTP hop.
2. azp vs client_id: Google uses azp; Auth0 and others sometimes use client_id. Should nodes check both claims, or pick one standard and require
   providers to use it?
3. Addition delay: Should adding a new issuer also require a delay (queue → execute), or is it immediate? Delaying additions reduces risk of
   accidentally trusting a wrong issuer, but slows onboarding.
4. Removal delay: Same removalDelay used for node removals, or a separate issuer-specific delay configured on the group?
5. JWT library: A few solid Go options — github.com/lestrrat-go/jwx/v3 handles full JWKS fetching/caching and RS256/ES256;
   github.com/golang-jwt/jwt/v5 is more minimal and we'd wire JWKS ourselves. Any preference?
6. Auth optional for testing? Should nodes accept requests without a JWT when no issuers are configured on the group (to keep devnet/tests working
   without a real OAuth provider)?
7. key_suffix separator: : (e.g. sub:savings) or something else?

1. Use OpenID Discovery
2. Check both claims. prefer azp.
3. adding and removing should have separate delays. initial list can be specified as part of contract creation.
4. separate issuer-specific delay configured on the group
5. use lestrrat-go
6. if groups have no configured issuers then auth is not necessary.
   6a. there should also be a configurable 'test mode' of the server when signature and expiration of tokens is not checked. this facilitates easier testing without constantly creating new tokens.
7. key suffix: : is good.

Critical Issue - Forwarding of raw JWT token to all nodes.

We will need a scheme where:
* An application uses social login - or a similar Oauth provider - to authenticate a user.
* After authentication, the application holds a JWT token on behalf of the user.
  * Assume that is token stays in the 'client' of the application - either in the browser, mobile app, etc.
* We need an inexpensive, fast way for the application - with 'client-side' code - to prove that there exists a valid signature for that JWT token.
* The JWT token can then be forwarded without the original signature - making it so that the token cannot be reused elsewhere.
* There likely needs to be some element of the proof that binds the proof to the current group, signing session etc.
  * In other words, there needs to be some replay protection on this proof as well.