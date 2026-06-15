package com.github.calcifux.authtoolkit.spring.method;

import com.github.calcifux.authtoolkit.Ability;
import com.github.calcifux.authtoolkit.AuthPrincipal;
import com.github.calcifux.authtoolkit.AuthorizationProfile;
import com.github.calcifux.authtoolkit.spring.AuthContext;
import com.github.calcifux.authtoolkit.spring.AuthResolverFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Bridges the toolkit's resolved identity into Spring Security's {@code SecurityContext} so
 * declarative method security works against OUR roles and abilities:
 * <ul>
 *   <li>each role becomes {@code ROLE_<code>} → {@code hasRole('EDITOR')};</li>
 *   <li>each ability becomes an authority via {@link AbilityAuthorityNaming}
 *       → {@code hasAnyAuthority('publish:article')}.</li>
 * </ul>
 *
 * <p>Runs just after {@link AuthResolverFilter} (which populated {@code AuthContext}) and
 * clears the security context in {@code finally}. Only active when method security is enabled.</p>
 */
public class SecurityContextBridgeFilter extends OncePerRequestFilter implements Ordered {

    private final AbilityAuthorityNaming naming;

    public SecurityContextBridgeFilter(AbilityAuthorityNaming naming) {
        this.naming = naming;
    }

    @Override
    public int getOrder() {
        // After AuthResolverFilter so AuthContext is already populated.
        return AuthResolverFilter.ORDER + 10;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        Optional<AuthPrincipal> principal = AuthContext.principal();
        boolean populated = false;
        if (principal.isPresent()) {
            AuthorizationProfile profile = AuthContext.profile();
            List<GrantedAuthority> authorities = new ArrayList<>();
            for (String role : profile.roles()) {
                authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
            }
            for (Ability ability : profile.abilities()) {
                authorities.add(new SimpleGrantedAuthority(naming.authority(ability)));
            }
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(principal.get(), "N/A", authorities);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            populated = true;
        }
        try {
            filterChain.doFilter(request, response);
        } finally {
            if (populated) {
                SecurityContextHolder.clearContext();
            }
        }
    }
}
