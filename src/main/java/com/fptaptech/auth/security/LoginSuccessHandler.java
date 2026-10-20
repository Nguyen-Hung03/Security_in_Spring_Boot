package com.fptaptech.auth.security;

import com.fptaptech.auth.audit.AuditEventType;
import com.fptaptech.auth.audit.AuditService;
import com.fptaptech.auth.devices.DeviceSessionService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import java.io.IOException;
import java.time.Instant;

public class LoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    private final AuditService audit;

    public LoginSuccessHandler(AuditService audit) {
        this.audit = audit;
        setDefaultTargetUrl("/");
        setAlwaysUseDefaultTargetUrl(false);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        HttpSession session = request.getSession();
        session.setAttribute(DeviceSessionService.LOGIN_IP, ClientInfo.ip(request));
        session.setAttribute(DeviceSessionService.LOGIN_UA, ClientInfo.userAgent(request));
        session.setAttribute(DeviceSessionService.LOGIN_AT, Instant.now().toString());
        session.setAttribute(DeviceSessionService.ACCOUNT_EMAIL, authentication.getName());
        boolean pending = authentication.getAuthorities().stream()
                .anyMatch(authority -> PortalAuthenticationProvider.PENDING_AUTHORITY.equals(authority.getAuthority()));
        if (pending) {
            getRedirectStrategy().sendRedirect(request, response, "/2fa");
            return;
        }
        session.setAttribute("TOTP_OK", Boolean.TRUE);
        audit.record(AuditEventType.LOGIN_SUCCESS, authentication.getName(), authentication.getName(), request, "Đăng nhập");
        if (authentication.getPrincipal() instanceof PortalUserDetails details && details.mustEnrollTotp()) {
            getRedirectStrategy().sendRedirect(request, response, "/account/2fa/setup");
            return;
        }
        super.onAuthenticationSuccess(request, response, authentication);
    }
}
