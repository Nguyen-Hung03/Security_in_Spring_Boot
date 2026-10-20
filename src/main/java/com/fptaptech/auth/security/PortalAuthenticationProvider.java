package com.fptaptech.auth.security;

import com.fptaptech.auth.account.LockoutService;
import com.fptaptech.auth.audit.AuditEventType;
import com.fptaptech.auth.audit.AuditService;
import com.fptaptech.auth.user.AccountStatus;
import com.fptaptech.auth.user.AuthSnapshot;
import com.fptaptech.auth.user.UserService;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import java.util.List;
import java.util.UUID;

@Component
public class PortalAuthenticationProvider implements AuthenticationProvider {

    public static final String PENDING_AUTHORITY = "ROLE_2FA_PENDING";

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final LockoutService lockout;
    private final AuditService audit;
    private final String dummyHash;

    public PortalAuthenticationProvider(UserService userService, PasswordEncoder passwordEncoder,
                                        LockoutService lockout, AuditService audit) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.lockout = lockout;
        this.audit = audit;
        this.dummyHash = passwordEncoder.encode("timing-" + UUID.randomUUID());
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        String rawName = authentication.getName() == null ? "" : authentication.getName();
        String rawPassword = authentication.getCredentials() == null ? "" : authentication.getCredentials().toString();
        String username = UserService.normalize(rawName);
        var request = Requests.current();
        if (username.length() > 254 || rawPassword.length() > 128) {
            passwordEncoder.matches("bounded-password", dummyHash);
            audit.record(AuditEventType.LOGIN_FAILURE, "rejected", null, request, "Dữ liệu đăng nhập không hợp lệ");
            throw new BadCredentialsException("Đăng nhập không thành công");
        }
        lockout.unlockIfExpired(username);
        AuthSnapshot snapshot = userService.loadSnapshot(username);
        boolean matches = passwordEncoder.matches(rawPassword, snapshot == null ? dummyHash : snapshot.passwordHash());
        if (snapshot != null && matches && passwordEncoder.upgradeEncoding(snapshot.passwordHash())) {
            userService.upgradeHash(snapshot.id(), passwordEncoder.encode(rawPassword));
        }
        boolean active = snapshot != null && snapshot.status() == AccountStatus.ACTIVE;
        if (!matches || !active) {
            if (!matches) {
                lockout.recordFailure(username, LockoutService.PASSWORD, request);
            }
            audit.record(AuditEventType.LOGIN_FAILURE, username, snapshot == null ? null : snapshot.email(), request,
                    "Đăng nhập không thành công");
            throw new BadCredentialsException("Đăng nhập không thành công");
        }
        PortalUserDetails details = userService.loadDetails(username);
        if (details.isTotpEnabled()) {
            return UsernamePasswordAuthenticationToken.authenticated(details, null,
                    List.of(new SimpleGrantedAuthority(PENDING_AUTHORITY)));
        }
        return UsernamePasswordAuthenticationToken.authenticated(details, null, details.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
