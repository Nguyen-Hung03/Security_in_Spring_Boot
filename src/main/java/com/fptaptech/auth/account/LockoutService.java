package com.fptaptech.auth.account;

import com.fptaptech.auth.audit.AuditEventType;
import com.fptaptech.auth.audit.AuditService;
import com.fptaptech.auth.user.AccountStatus;
import com.fptaptech.auth.user.AppUser;
import com.fptaptech.auth.user.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import java.time.Duration;
import java.time.Instant;

@Service
public class LockoutService {

    public static final String PASSWORD = "PASSWORD";
    public static final String TOTP = "TOTP";
    public static final int LIMIT = 5;
    public static final Duration WINDOW = Duration.ofMinutes(15);

    private final LoginAttemptRepository attempts;
    private final UserRepository users;
    private final AuditService audit;

    public LockoutService(LoginAttemptRepository attempts, UserRepository users, AuditService audit) {
        this.attempts = attempts;
        this.users = users;
        this.audit = audit;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void unlockIfExpired(String username) {
        users.findByUsername(username).ifPresent(user -> {
            if (user.getStatus() == AccountStatus.LOCKED
                    && user.getLockedUntil() != null
                    && !user.getLockedUntil().isAfter(Instant.now())) {
                user.setStatus(AccountStatus.ACTIVE);
                user.setEnabled(true);
                user.setLockedUntil(null);
            }
        });
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordFailure(String username, String kind, HttpServletRequest request) {
        Instant now = Instant.now();
        attempts.deleteByAttemptedAtBefore(now.minus(Duration.ofDays(1)));
        attempts.save(new LoginAttempt(username, false, kind, now));
        AppUser user = users.findByUsername(username).orElse(null);
        if (user == null || user.getStatus() != AccountStatus.ACTIVE) {
            return;
        }
        long count = attempts.countByUsernameAndSuccessFalseAndKindAndAttemptedAtAfter(
                username, kind, now.minus(WINDOW));
        if (count >= LIMIT && (user.getLockedUntil() == null || !user.getLockedUntil().isAfter(now))) {
            user.setStatus(AccountStatus.LOCKED);
            user.setEnabled(false);
            user.setLockedUntil(now.plus(WINDOW));
            audit.record(AuditEventType.ACCOUNT_LOCKED, username, username, request, "Khóa tạm thời 15 phút");
        }
    }
}
