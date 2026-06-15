package com.github.calcifux.authtoolkit.spring.web;

import com.github.calcifux.authtoolkit.AuthPrincipal;
import com.github.calcifux.authtoolkit.AuthorizationProfile;
import com.github.calcifux.authtoolkit.spring.Auth;
import com.github.calcifux.authtoolkit.spring.AuthContext;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;
import org.springframework.web.server.ResponseStatusException;

import java.util.Optional;
import java.util.UUID;

/**
 * Resolves controller parameters annotated with {@link CurrentUser} from the per-request
 * {@code AuthContext}. Supports {@link AuthPrincipal}, {@link UUID} (the local user id),
 * {@link AuthorizationProfile} and {@code Optional<AuthPrincipal>}.
 */
public class CurrentUserArgumentResolver implements HandlerMethodArgumentResolver {

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.hasParameterAnnotation(CurrentUser.class);
    }

    @Override
    public Object resolveArgument(
            MethodParameter parameter,
            ModelAndViewContainer mavContainer,
            NativeWebRequest webRequest,
            WebDataBinderFactory binderFactory) {

        Optional<AuthPrincipal> principal = Auth.principal();

        CurrentUser annotation = parameter.getParameterAnnotation(CurrentUser.class);
        if (annotation != null && annotation.required() && principal.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }

        Class<?> type = parameter.getParameterType();
        if (Optional.class.equals(type)) {
            return principal;
        }
        if (AuthPrincipal.class.equals(type)) {
            return principal.orElse(null);
        }
        if (UUID.class.equals(type)) {
            return principal.map(AuthPrincipal::userId).orElse(null);
        }
        if (AuthorizationProfile.class.equals(type)) {
            return AuthContext.profile();
        }
        throw new IllegalStateException("@CurrentUser does not support parameter type " + type.getName()
                + " — use AuthPrincipal, UUID, AuthorizationProfile or Optional<AuthPrincipal>");
    }
}
