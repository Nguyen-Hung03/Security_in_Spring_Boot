package com.fptaptech.auth.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.util.List;

public class TwoFactorRememberMeFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof RememberMeAuthenticationToken
                && authentication.getPrincipal() instanceof PortalUserDetails details
                && details.isTotpEnabled()
                && !Boolean.TRUE.equals(request.getSession().getAttribute("TOTP_OK"))) {
            var pending = UsernamePasswordAuthenticationToken.authenticated(details, null,
                    List.of(new SimpleGrantedAuthority(PortalAuthenticationProvider.PENDING_AUTHORITY)));
            var context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(pending);
            SecurityContextHolder.setContext(context);
            String path = Requests.path(request);
            if (!"/2fa".equals(path) && !"/logout".equals(path)) {
                response.sendRedirect(request.getContextPath() + "/2fa");
                return;
            }
        }
        chain.doFilter(request, response);
    }
}
