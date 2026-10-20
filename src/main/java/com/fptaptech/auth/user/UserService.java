package com.fptaptech.auth.user;

import com.fptaptech.auth.audit.AuditEventType;
import com.fptaptech.auth.audit.AuditService;
import com.fptaptech.auth.config.AppProperties;
import com.fptaptech.auth.devices.DeviceSessionService;
import com.fptaptech.auth.mail.EmailGateway;
import com.fptaptech.auth.mail.MailMessages;
import com.fptaptech.auth.password.PasswordPolicy;
import com.fptaptech.auth.security.PortalUserDetails;
import com.fptaptech.auth.security.Requests;
import com.fptaptech.auth.token.EmailToken;
import com.fptaptech.auth.token.EmailTokenPurpose;
import com.fptaptech.auth.token.InvalidTokenException;
import com.fptaptech.auth.token.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Locale;

@Service
public class UserService {

    private static final Duration VERIFY_TTL = Duration.ofHours(24);
    private static final Duration RESET_TTL = Duration.ofMinutes(30);

    private final UserRepository users;
    private final RoleRepository roles;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicy passwordPolicy;
    private final PasswordHistoryRepository history;
    private final TokenService tokenService;
    private final EmailGateway emailGateway;
    private final AppProperties properties;
    private final AuditService audit;
    private final DeviceSessionService devices;
    private final PersistentTokenRepository rememberMe;

    public UserService(UserRepository users, RoleRepository roles, PasswordEncoder passwordEncoder,
                       PasswordPolicy passwordPolicy, PasswordHistoryRepository history, TokenService tokenService,
                       EmailGateway emailGateway, AppProperties properties, AuditService audit,
                       DeviceSessionService devices, PersistentTokenRepository rememberMe) {
        this.users = users;
        this.roles = roles;
        this.passwordEncoder = passwordEncoder;
        this.passwordPolicy = passwordPolicy;
        this.history = history;
        this.tokenService = tokenService;
        this.emailGateway = emailGateway;
        this.properties = properties;
        this.audit = audit;
        this.devices = devices;
        this.rememberMe = rememberMe;
    }

    public static String normalize(String username) {
        return username == null ? "" : username.trim().toLowerCase(Locale.ROOT);
    }

    @Transactional(readOnly = true)
    public AuthSnapshot loadSnapshot(String username) {
        return users.findByUsername(username)
                .map(user -> new AuthSnapshot(user.getId(), user.getEmail(), user.getPasswordHash(), user.getStatus(),
                        user.getLockedUntil(), user.isTotpEnabled(), user.isEnabled()))
                .orElse(null);
    }

    @Transactional(readOnly = true)
    public PortalUserDetails loadDetails(String username) {
        AppUser user = users.findWithRolesByUsername(username)
                .orElseThrow(() -> new IllegalStateException("Không tìm thấy tài khoản"));
        return PortalUserDetails.from(user);
    }

    @Transactional
    public void upgradeHash(Long id, String newHash) {
        AppUser user = users.findById(id).orElseThrow();
        if (!passwordEncoder.upgradeEncoding(user.getPasswordHash())) {
            return;
        }
        history.save(new PasswordHistory(user, user.getPasswordHash(), Instant.now()));
        user.setPasswordHash(newHash);
        user.setPasswordChangedAt(Instant.now());
    }

    @Transactional
    public AppUser register(String rawEmail, String fullName, String rawPassword) {
        String email = normalize(rawEmail);
        rejectWeak(rawPassword, email);
        if (users.existsByUsername(email)) {
            throw new UsernameAlreadyExistsException(email);
        }
        Role student = roles.findByName(Role.STUDENT)
                .orElseThrow(() -> new IllegalStateException("Thiếu dữ liệu vai trò ROLE_STUDENT"));
        AppUser user = new AppUser(email, passwordEncoder.encode(rawPassword));
        user.setFullName(fullName.trim());
        user.setStatus(AccountStatus.PENDING);
        user.setEnabled(false);
        user.getRoles().add(student);
        try {
            users.saveAndFlush(user);
        } catch (DataIntegrityViolationException ex) {
            throw new UsernameAlreadyExistsException(email);
        }
        String token = tokenService.issue(user, EmailTokenPurpose.VERIFY_EMAIL, VERIFY_TTL);
        sendAfterCommit(email, "Xác minh tài khoản FPT Aptech",
                MailMessages.verify(user.getFullName(), properties.baseUrl() + "/verify-email?token=" + token));
        audit.record(AuditEventType.REGISTERED, email, email, Requests.current(), "Đăng ký tài khoản học viên");
        return user;
    }

    @Transactional
    public void resendVerification(String rawEmail) {
        String email = normalize(rawEmail);
        AppUser user = users.findByUsername(email).orElse(null);
        if (user == null || user.getStatus() != AccountStatus.PENDING) {
            return;
        }
        if (tokenService.recentCount(user.getId(), EmailTokenPurpose.VERIFY_EMAIL, Duration.ofHours(1)) >= 4) {
            return;
        }
        String token = tokenService.issue(user, EmailTokenPurpose.VERIFY_EMAIL, VERIFY_TTL);
        sendAfterCommit(email, "Xác minh tài khoản FPT Aptech",
                MailMessages.verify(user.getFullName(), properties.baseUrl() + "/verify-email?token=" + token));
    }

    @Transactional
    public void verifyEmail(String rawToken) {
        EmailToken token = tokenService.consume(rawToken, java.util.Set.of(EmailTokenPurpose.VERIFY_EMAIL));
        AppUser user = token.getUser();
        if (user.getStatus() != AccountStatus.PENDING) {
            throw new InvalidTokenException();
        }
        user.setStatus(AccountStatus.ACTIVE);
        user.setEnabled(true);
        audit.record(AuditEventType.EMAIL_VERIFIED, user.getEmail(), user.getEmail(), Requests.current(), "Xác minh email");
    }

    @Transactional
    public void requestPasswordReset(String rawEmail) {
        String email = normalize(rawEmail);
        AppUser user = users.findByUsername(email).orElse(null);
        if (user == null || (user.getStatus() != AccountStatus.ACTIVE && user.getStatus() != AccountStatus.LOCKED)) {
            return;
        }
        String token = tokenService.issue(user, EmailTokenPurpose.PASSWORD_RESET, RESET_TTL);
        sendAfterCommit(email, "Đặt lại mật khẩu FPT Aptech",
                MailMessages.reset(properties.baseUrl() + "/reset-password?token=" + token));
    }

    @Transactional
    public void completePasswordToken(String rawToken, String newPassword) {
        EmailToken token = tokenService.peek(rawToken, TokenService.passwordPurposes());
        AppUser user = token.getUser();
        if (user.getStatus() != AccountStatus.ACTIVE
                && user.getStatus() != AccountStatus.LOCKED
                && user.getStatus() != AccountStatus.INVITED) {
            throw new InvalidTokenException();
        }
        checkReusable(user, newPassword);
        tokenService.consume(rawToken, TokenService.passwordPurposes());
        storePassword(user, newPassword);
        user.setStatus(AccountStatus.ACTIVE);
        user.setEnabled(true);
        user.setLockedUntil(null);
        devices.revokeAll(user.getUsername());
        rememberMe.removeUserTokens(user.getUsername());
        audit.record(AuditEventType.PASSWORD_RESET, user.getEmail(), user.getEmail(), Requests.current(), "Đặt lại mật khẩu");
    }

    @Transactional
    public void changePassword(Long userId, String currentPassword, String newPassword, String currentSessionId) {
        AppUser user = users.findById(userId).orElseThrow();
        if (!passwordEncoder.matches(currentPassword, user.getPasswordHash())) {
            throw new WeakPasswordException("Mật khẩu hiện tại không đúng");
        }
        checkReusable(user, newPassword);
        storePassword(user, newPassword);
        devices.revokeOthers(user.getUsername(), currentSessionId);
        rememberMe.removeUserTokens(user.getUsername());
        audit.record(AuditEventType.PASSWORD_CHANGED, user.getEmail(), user.getEmail(), Requests.current(), "Đổi mật khẩu");
    }

    @Transactional
    public void updateProfile(Long userId, String fullName, String phone) {
        AppUser user = users.findById(userId).orElseThrow();
        user.setFullName(fullName.trim());
        user.setPhone(phone == null || phone.isBlank() ? null : phone.trim());
    }

    @Transactional
    public void createBootstrapAdmin(String email, String fullName, String rawPassword) {
        String normalized = normalize(email);
        if (users.existsByUsername(normalized) || users.countByRoleAndStatus(Role.ADMIN, AccountStatus.ACTIVE) > 0) {
            return;
        }
        rejectWeak(rawPassword, normalized);
        Role admin = roles.findByName(Role.ADMIN)
                .orElseThrow(() -> new IllegalStateException("Thiếu dữ liệu vai trò ROLE_ADMIN"));
        AppUser user = new AppUser(normalized, passwordEncoder.encode(rawPassword));
        user.setFullName(fullName);
        user.setStatus(AccountStatus.ACTIVE);
        user.setEnabled(true);
        user.getRoles().add(admin);
        users.save(user);
    }

    public void rejectWeak(String rawPassword, String email) {
        passwordPolicy.validate(rawPassword, email).ifPresent(message -> {
            throw new WeakPasswordException(message);
        });
    }

    private void checkReusable(AppUser user, String rawPassword) {
        rejectWeak(rawPassword, user.getEmail());
        if (passwordEncoder.matches(rawPassword, user.getPasswordHash())) {
            throw new WeakPasswordException("Mật khẩu trùng với một trong 5 mật khẩu gần nhất");
        }
        for (PasswordHistory previous : history.findTop5ByUserIdOrderByCreatedAtDesc(user.getId())) {
            if (passwordEncoder.matches(rawPassword, previous.getPasswordHash())) {
                throw new WeakPasswordException("Mật khẩu trùng với một trong 5 mật khẩu gần nhất");
            }
        }
    }

    private void storePassword(AppUser user, String rawPassword) {
        history.saveAndFlush(new PasswordHistory(user, user.getPasswordHash(), Instant.now()));
        var existing = history.findByUserIdOrderByCreatedAtDesc(user.getId());
        if (existing.size() > 5) {
            history.deleteAll(new ArrayList<>(existing.subList(5, existing.size())));
        }
        user.setPasswordHash(passwordEncoder.encode(rawPassword));
        user.setPasswordChangedAt(Instant.now());
    }

    private void sendAfterCommit(String to, String subject, String body) {
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    emailGateway.send(to, subject, body);
                }
            });
        } else {
            emailGateway.send(to, subject, body);
        }
    }
}
