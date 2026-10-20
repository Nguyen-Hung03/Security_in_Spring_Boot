package com.fptaptech.auth.user;

import com.fptaptech.auth.audit.AuditEventType;
import com.fptaptech.auth.audit.AuditService;
import com.fptaptech.auth.config.AppProperties;
import com.fptaptech.auth.devices.DeviceSessionService;
import com.fptaptech.auth.mail.EmailGateway;
import com.fptaptech.auth.mail.MailMessages;
import com.fptaptech.auth.security.Requests;
import com.fptaptech.auth.token.EmailTokenPurpose;
import com.fptaptech.auth.token.TokenService;
import com.fptaptech.auth.totp.TotpService;
import com.fptaptech.auth.web.TimeFormat;
import com.fptaptech.auth.web.UserSummary;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;

@Service
public class AdminUserService {

    private static final String LAST_ADMIN = "Hệ thống phải còn ít nhất một quản trị viên đang hoạt động";

    private final UserRepository users;
    private final RoleRepository roles;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;
    private final EmailGateway emailGateway;
    private final AppProperties properties;
    private final AuditService audit;
    private final DeviceSessionService devices;
    private final PersistentTokenRepository rememberMe;
    private final TotpService totpService;
    private final SecureRandom random = new SecureRandom();

    public AdminUserService(UserRepository users, RoleRepository roles, PasswordEncoder passwordEncoder,
                            TokenService tokenService, EmailGateway emailGateway, AppProperties properties,
                            AuditService audit, DeviceSessionService devices, PersistentTokenRepository rememberMe,
                            TotpService totpService) {
        this.users = users;
        this.roles = roles;
        this.passwordEncoder = passwordEncoder;
        this.tokenService = tokenService;
        this.emailGateway = emailGateway;
        this.properties = properties;
        this.audit = audit;
        this.devices = devices;
        this.rememberMe = rememberMe;
        this.totpService = totpService;
    }

    @Transactional(readOnly = true)
    public Page<UserSummary> search(String email, AccountStatus status, String role, Pageable pageable) {
        Pageable limited = PageRequest.of(pageable.getPageNumber(), Math.min(pageable.getPageSize(), 50), pageable.getSort());
        return users.search(blankToNull(email), status, blankToNull(role), limited).map(this::toSummary);
    }

    @Transactional(readOnly = true)
    public Page<UserSummary> students(Pageable pageable) {
        Pageable limited = PageRequest.of(pageable.getPageNumber(), Math.min(pageable.getPageSize(), 50), pageable.getSort());
        return users.findByRoleName(Role.STUDENT, limited).map(this::toSummary);
    }

    @Transactional(readOnly = true)
    public UserSummary get(Long id) {
        return toSummary(users.findWithRolesById(id).orElseThrow());
    }

    @Transactional
    public void invite(String rawEmail, String fullName, String roleName) {
        if (!Role.LECTURER.equals(roleName) && !Role.ADMIN.equals(roleName)) {
            throw new IllegalArgumentException("Chỉ được mời giảng viên hoặc quản trị viên");
        }
        String email = UserService.normalize(rawEmail);
        if (users.existsByUsername(email)) {
            throw new UsernameAlreadyExistsException(email);
        }
        byte[] secret = new byte[32];
        random.nextBytes(secret);
        AppUser user = new AppUser(email, passwordEncoder.encode(Base64.getUrlEncoder().withoutPadding().encodeToString(secret)));
        user.setFullName(fullName.trim());
        user.setStatus(AccountStatus.INVITED);
        user.setEnabled(false);
        user.getRoles().add(roles.findByName(roleName).orElseThrow());
        try {
            users.saveAndFlush(user);
        } catch (DataIntegrityViolationException ex) {
            throw new UsernameAlreadyExistsException(email);
        }
        String token = tokenService.issue(user, EmailTokenPurpose.INVITE, Duration.ofHours(24));
        String label = Role.ADMIN.equals(roleName) ? "quản trị viên" : "giảng viên";
        sendAfterCommit(email, "Lời mời tài khoản FPT Aptech",
                MailMessages.invite(user.getFullName(), label, properties.baseUrl() + "/reset-password?token=" + token));
        audit.record(AuditEventType.INVITED, actor(), email, Requests.current(), "Mời vai trò " + roleName);
    }

    @Transactional
    public void changeRole(Long actorId, Long userId, String roleName) {
        if (!Role.STUDENT.equals(roleName) && !Role.LECTURER.equals(roleName) && !Role.ADMIN.equals(roleName)) {
            throw new IllegalArgumentException("Vai trò không hợp lệ");
        }
        AppUser user = users.findWithRolesById(userId).orElseThrow();
        boolean removesAdmin = user.hasRole(Role.ADMIN) && !Role.ADMIN.equals(roleName);
        if (removesAdmin && isLastActiveAdmin(user)) {
            throw new AdminRuleException(LAST_ADMIN);
        }
        if (removesAdmin && user.getId().equals(actorId)) {
            throw new AdminRuleException("Bạn không thể tự gỡ quyền quản trị của chính mình");
        }
        user.getRoles().clear();
        user.getRoles().add(roles.findByName(roleName).orElseThrow());
        audit.record(AuditEventType.ROLE_CHANGED, actor(), user.getEmail(), Requests.current(), "Vai trò mới " + roleName);
    }

    @Transactional
    public void disable(Long actorId, Long userId) {
        AppUser user = users.findWithRolesById(userId).orElseThrow();
        if (isActiveAdmin(user) && isLastActiveAdmin(user)) {
            throw new AdminRuleException(LAST_ADMIN);
        }
        if (user.getId().equals(actorId)) {
            throw new AdminRuleException("Bạn không thể tự vô hiệu hóa tài khoản của mình");
        }
        user.setStatus(AccountStatus.DISABLED);
        user.setEnabled(false);
        user.setLockedUntil(null);
        revokeAccess(user.getUsername());
        audit.record(AuditEventType.ACCOUNT_DISABLED, actor(), user.getEmail(), Requests.current(), "Vô hiệu hóa tài khoản");
    }

    @Transactional
    public void enable(Long userId) {
        AppUser user = users.findWithRolesById(userId).orElseThrow();
        if (user.getStatus() != AccountStatus.DISABLED && user.getStatus() != AccountStatus.LOCKED) {
            return;
        }
        AuditEventType type = user.getStatus() == AccountStatus.LOCKED
                ? AuditEventType.ACCOUNT_UNLOCKED : AuditEventType.ACCOUNT_ENABLED;
        user.setStatus(AccountStatus.ACTIVE);
        user.setEnabled(true);
        user.setLockedUntil(null);
        audit.record(type, actor(), user.getEmail(), Requests.current(), "Mở lại tài khoản");
    }

    @Transactional
    public void forceLogout(Long userId) {
        AppUser user = users.findById(userId).orElseThrow();
        revokeAccess(user.getUsername());
        audit.record(AuditEventType.SESSION_REVOKED, actor(), user.getEmail(), Requests.current(), "Buộc đăng xuất");
    }

    @Transactional
    public void delete(Long actorId, Long userId) {
        AppUser user = users.findWithRolesById(userId).orElseThrow();
        if (isActiveAdmin(user) && isLastActiveAdmin(user)) {
            throw new AdminRuleException(LAST_ADMIN);
        }
        if (user.getId().equals(actorId)) {
            throw new AdminRuleException("Bạn không thể tự xóa tài khoản của mình");
        }
        String email = user.getUsername();
        revokeAccess(email);
        users.delete(user);
        audit.record(AuditEventType.ACCOUNT_DELETED, actor(), email, Requests.current(), "Xóa tài khoản");
    }

    @Transactional
    public void resetTotp(Long userId) {
        totpService.adminReset(userId, actor());
    }

    private void revokeAccess(String username) {
        devices.revokeAll(username);
        rememberMe.removeUserTokens(username);
    }

    private boolean isActiveAdmin(AppUser user) {
        return user.getStatus() == AccountStatus.ACTIVE && user.hasRole(Role.ADMIN);
    }

    private boolean isLastActiveAdmin(AppUser user) {
        return isActiveAdmin(user) && users.countByRoleAndStatus(Role.ADMIN, AccountStatus.ACTIVE) <= 1;
    }

    private UserSummary toSummary(AppUser user) {
        String role = user.getRoles().stream().map(Role::getName).sorted().findFirst().orElse("");
        return new UserSummary(user.getId(), user.getEmail(), user.getFullName(), user.getPhone(),
                user.getStatus().name(), role, user.isTotpEnabled(), TimeFormat.format(user.getCreatedAt()),
                TimeFormat.format(user.getLockedUntil()));
    }

    private String actor() {
        HttpServletRequest request = Requests.current();
        if (request != null && request.getUserPrincipal() != null) {
            return request.getUserPrincipal().getName();
        }
        return "system";
    }

    private String blankToNull(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String cleaned = value.trim().replace("%", "").replace("_", "");
        return cleaned.isBlank() ? null : cleaned;
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
