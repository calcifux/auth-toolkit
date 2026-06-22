package com.github.calcifux.authtoolkit.quarkus.method;

import com.github.calcifux.authtoolkit.quarkus.Auth;
import jakarta.annotation.Priority;
import jakarta.interceptor.AroundInvoke;
import jakarta.interceptor.Interceptor;
import jakarta.interceptor.InvocationContext;
import jakarta.ws.rs.ForbiddenException;

import java.util.Set;

/**
 * Aplica {@link AuthCan}: lee la regla de la anotación (del método; si no, de la clase) y concede el acceso si
 * pasa AL MENOS UNA de sus comprobaciones — habilidad {@code action}/{@code subject} ({@code Auth.can}), cualquiera
 * de {@code anyAuthority} ({@code "action:subject"}), o cualquiera de {@code anyRole} ({@code Auth.roles()}). Si no,
 * lanza 403 ({@code ForbiddenException}).
 *
 * <p>Lee la identidad de la petición a través de la fachada {@link Auth} (el {@code AuthContext} que pobló el
 * resolver de la app). Prioridad temprana ({@code PLATFORM_BEFORE + 100}): rechaza antes de abrir transacción o
 * tocar el dominio. Se autodescubre por el índice Jandex del jar (sin {@code beans.xml}).</p>
 */
@AuthCan(action = "", subject = "")
@Interceptor
@Priority(Interceptor.Priority.PLATFORM_BEFORE + 100)
public class AuthCanInterceptor {

    @AroundInvoke
    Object enforce(InvocationContext context) throws Exception {
        AuthCan rule = resolveRule(context);
        if (rule != null && !isGranted(rule)) {
            throw new ForbiddenException(describe(rule));
        }
        return context.proceed();
    }

    private boolean isGranted(AuthCan rule) {
        boolean hasAnyCheck = !rule.action().isEmpty() || rule.anyAuthority().length > 0 || rule.anyRole().length > 0;
        if (!hasAnyCheck) {
            return true; // anotación sin comprobaciones = no-op
        }
        if (!rule.action().isEmpty() && Auth.can(rule.action(), rule.subject())) {
            return true;
        }
        for (String authority : rule.anyAuthority()) {
            String[] parts = authority.split(":", 2);
            if (parts.length == 2 && Auth.can(parts[0].trim(), parts[1].trim())) {
                return true;
            }
        }
        Set<String> roles = Auth.roles();
        for (String role : rule.anyRole()) {
            if (roles.contains(role)) {
                return true;
            }
        }
        return false;
    }

    /** Mensaje del 403 (solo para logs; el cliente recibe el cuerpo de error genérico de la app). */
    private String describe(AuthCan rule) {
        if (!rule.action().isEmpty()) {
            return rule.action() + ":" + rule.subject();
        }
        if (rule.anyAuthority().length > 0) {
            return String.join("|", rule.anyAuthority());
        }
        return "role:" + String.join("|", rule.anyRole());
    }

    /** La anotación del MÉTODO gana; si el método no la lleva, se usa la de la CLASE. */
    private AuthCan resolveRule(InvocationContext context) {
        AuthCan onMethod = context.getMethod().getAnnotation(AuthCan.class);
        return onMethod != null
                ? onMethod
                : context.getMethod().getDeclaringClass().getAnnotation(AuthCan.class);
    }
}
