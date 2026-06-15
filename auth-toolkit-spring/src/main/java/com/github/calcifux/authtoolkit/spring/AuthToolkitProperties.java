package com.github.calcifux.authtoolkit.spring;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/**
 * Externalized configuration, bound from {@code auth.toolkit.*}. Each adapter is turned
 * on by its own {@code enabled} flag, so you can run one provider (the appliance norm)
 * or stack several in the chain.
 *
 * <pre>{@code
 * auth:
 *   toolkit:
 *     skip-paths: [/actuator]
 *     session:                # opaque HttpOnly cookie (SPA front-channel)
 *       enabled: true
 *       cookie-name: app_session
 *     jwt:                    # bearer tokens (API / services)
 *       enabled: false
 *       issuer: https://login.microsoftonline.com/<tenant>/v2.0
 *       jwks-uri: https://login.microsoftonline.com/<tenant>/discovery/v2.0/keys
 *       audience: <your-api-id>
 *       external-id-claim: oid
 *     header:                 # dev / trusted-proxy
 *       enabled: false
 * }</pre>
 */
@Data
@ConfigurationProperties(prefix = "auth.toolkit")
public class AuthToolkitProperties {

    /** URI prefixes the resolver filter skips entirely (e.g. {@code /actuator}). */
    private List<String> skipPaths = List.of("/actuator");

    private Header header = new Header();
    private Jwt jwt = new Jwt();
    private Session session = new Session();
    private MethodSecurity methodSecurity = new MethodSecurity();

    /** Dev / trusted-proxy header adapter. */
    @Data
    public static class Header {
        /** Toggle the header adapter. Default off (it trusts the caller). */
        private boolean enabled = false;
        /** Header carrying the LOCAL user id (UUID). */
        private String user = "X-User-Id";
        /** Header carrying the role. */
        private String role = "X-User-Role";
        /** Role value that marks an internal operator. */
        private String operatorRole = "operator";
    }

    /** Bearer-JWT adapter (self / Passport / Entra / OIDC). Needs a {@code PrincipalMapper} bean. */
    @Data
    public static class Jwt {
        /** Toggle the bearer-JWT adapter. */
        private boolean enabled = false;
        /** Header carrying the bearer token. */
        private String bearerHeader = "Authorization";
        /** Expected issuer ({@code iss}); null skips the check. */
        private String issuer;
        /** JWKS endpoint for RS* verification. */
        private String jwksUri;
        /** Shared secret for HS* verification (use jwksUri instead when you can). */
        private String hmacSecret;
        /** Expected audience ({@code aud}); null skips the check. */
        private String audience;
        /** Claim holding the stable subject (default {@code sub}; Entra {@code oid}). */
        private String externalIdClaim = "sub";
        /** Claim holding the email. */
        private String emailClaim = "email";
        /** Claim holding the display name. */
        private String nameClaim = "name";
    }

    /** Opaque cookie-session adapter. Needs a {@code TokenIntrospector} + {@code PrincipalMapper} bean. */
    @Data
    public static class Session {
        /** Toggle the cookie-session adapter. */
        private boolean enabled = false;
        /** Name of the opaque session cookie. */
        private String cookieName = "session";
    }

    /** Spring Security method-security bridge (@PreAuthorize). Needs Spring Security on the classpath. */
    @Data
    public static class MethodSecurity {
        /**
         * When true (and Spring Security is present), enables {@code @EnableMethodSecurity} and
         * bridges the resolved roles/abilities into the Spring {@code SecurityContext} as authorities,
         * so {@code @PreAuthorize("hasAnyAuthority('publish:article')")} / {@code hasRole('EDITOR')}
         * and {@code @PreAuthorize("@authz.can('publish','article')")} work.
         */
        private boolean enabled = false;
    }
}
