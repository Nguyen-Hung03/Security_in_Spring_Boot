package com.fptaptech.auth;

import com.fptaptech.auth.audit.AuditEventType;
import com.fptaptech.auth.audit.AuditRepository;
import com.fptaptech.auth.mail.CapturingEmailGateway;
import com.fptaptech.auth.security.Hashes;
import com.fptaptech.auth.token.EmailTokenRepository;
import com.fptaptech.auth.totp.Totp;
import com.fptaptech.auth.user.AccountStatus;
import com.fptaptech.auth.user.AppUser;
import com.fptaptech.auth.user.Role;
import com.fptaptech.auth.user.RoleRepository;
import com.fptaptech.auth.user.UserRepository;
import com.fptaptech.auth.user.UserService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import jakarta.servlet.http.Cookie;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.flash;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class PortalFlowTest {

    private static final String PASSWORD = "Correct#Horse2026";
    private static final String ADMIN_EMAIL = "admin@fptaptech.edu.vn";
    private static final String ADMIN_PASSWORD = "Portal#Secure2026!";
    private static String adminSecret;

    @Autowired MockMvc mvc;
    @Autowired CapturingEmailGateway mail;
    @Autowired UserRepository users;
    @Autowired RoleRepository roles;
    @Autowired EmailTokenRepository tokens;
    @Autowired UserService userService;
    @Autowired PasswordEncoder passwordEncoder;
    @Autowired AuditRepository audit;

    @Test
    void anonymousUserIsRedirectedToLogin() throws Exception {
        mvc.perform(get("/"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login"));
    }

    @Test
    void emptyRegistrationShowsVietnameseErrors() throws Exception {
        mvc.perform(post("/registration").with(csrf())
                        .param("email", "")
                        .param("fullName", "")
                        .param("password", "")
                        .param("passwordConfirm", ""))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Không được để trống")));
    }

    @Test
    void registrationStaysPendingUntilEmailIsVerified() throws Exception {
        String email = email("pending");
        register(email);
        AppUser user = users.findByUsername(email).orElseThrow();
        assertThat(user.getStatus()).isEqualTo(AccountStatus.PENDING);
        String raw = tokenFrom(email);
        assertThat(tokens.findByTokenHash(Hashes.sha256(raw))).isPresent();
        assertThat(tokens.findByTokenHash(raw)).isEmpty();
        mvc.perform(post("/login").with(csrf()).param("username", email).param("password", PASSWORD))
                .andExpect(redirectedUrl("/login?error"))
                .andExpect(unauthenticated());
        mvc.perform(get("/verify-email").param("token", raw))
                .andExpect(redirectedUrl("/login?verified"));
        assertThat(users.findByUsername(email).orElseThrow().getStatus()).isEqualTo(AccountStatus.ACTIVE);
        mvc.perform(post("/login").with(csrf()).param("username", email).param("password", PASSWORD))
                .andExpect(redirectedUrl("/"))
                .andExpect(authenticated().withUsername(email).withRoles("STUDENT"));
    }

    @Test
    void expiredAndReusedVerificationTokensFail() throws Exception {
        String expiredEmail = email("expired");
        register(expiredEmail);
        String raw = tokenFrom(expiredEmail);
        var token = tokens.findByTokenHash(Hashes.sha256(raw)).orElseThrow();
        token.setExpiresAt(Instant.now().minusSeconds(60));
        tokens.save(token);
        mvc.perform(get("/verify-email").param("token", raw))
                .andExpect(redirectedUrl("/login?verifyError"));
        assertThat(users.findByUsername(expiredEmail).orElseThrow().getStatus()).isEqualTo(AccountStatus.PENDING);

        String reuseEmail = email("reuse");
        register(reuseEmail);
        String reuse = tokenFrom(reuseEmail);
        mvc.perform(get("/verify-email").param("token", reuse)).andExpect(redirectedUrl("/login?verified"));
        mvc.perform(get("/verify-email").param("token", reuse)).andExpect(redirectedUrl("/login?verifyError"));
        assertThat(users.findByUsername(reuseEmail).orElseThrow().getStatus()).isEqualTo(AccountStatus.ACTIVE);
    }

    @Test
    void resendVerificationIsLimitedToThreePerHour() throws Exception {
        String email = email("resend");
        register(email);
        Long userId = users.findByUsername(email).orElseThrow().getId();
        for (int i = 0; i < 4; i++) {
            mvc.perform(post("/verification/resend").with(csrf()).param("email", email))
                    .andExpect(redirectedUrl("/login?resent"));
        }
        assertThat(tokens.countByUserIdAndPurposeAndCreatedAtAfter(
                userId, com.fptaptech.auth.token.EmailTokenPurpose.VERIFY_EMAIL, Instant.now().minusSeconds(3600)))
                .isEqualTo(4);
    }

    @Test
    void duplicateEmailAndMismatchedPasswordsAreRejected() throws Exception {
        String email = activeStudent();
        mvc.perform(post("/registration").with(csrf()).with(remote(email + "-dup"))
                        .param("email", email.toUpperCase())
                        .param("fullName", "Hoc Vien")
                        .param("password", PASSWORD)
                        .param("passwordConfirm", PASSWORD))
                .andExpect(status().isOk())
                .andExpect(model().attributeHasFieldErrorCode("form", "email", "registration.email.duplicate"))
                .andExpect(unauthenticated());
        mvc.perform(post("/registration").with(csrf()).with(remote(email + "-mismatch"))
                        .param("email", email("mismatch"))
                        .param("fullName", "Hoc Vien")
                        .param("password", PASSWORD)
                        .param("passwordConfirm", "Other#Horse2026"))
                .andExpect(status().isOk())
                .andExpect(model().attributeHasFieldErrors("form", "passwordConfirm"));
    }

    @Test
    void forgotPasswordResponseDoesNotRevealWhetherEmailExists() throws Exception {
        String email = activeStudent();
        mvc.perform(post("/forgot-password").with(csrf()).with(remote("forgot-yes"))
                        .param("email", email))
                .andExpect(redirectedUrl("/forgot-password/sent"));
        mvc.perform(post("/forgot-password").with(csrf()).with(remote("forgot-no"))
                        .param("email", "missing-person@example.com"))
                .andExpect(redirectedUrl("/forgot-password/sent"));
        String page = mvc.perform(get("/forgot-password/sent")).andReturn().getResponse().getContentAsString();
        assertThat(page).contains("Nếu email tồn tại trong hệ thống");
        assertThat(mail.latestTo(email)).isNotNull();
        assertThat(mail.latestTo("missing-person@example.com")).isNull();
    }

    @Test
    void expiredOrReusedResetTokenDoesNotChangePasswordAndResetRevokesSessions() throws Exception {
        String email = activeStudent();
        Cookie session = login(email, PASSWORD);
        mvc.perform(post("/forgot-password").with(csrf()).with(remote("reset-" + email)).param("email", email));
        String raw = tokenFrom(email);
        var token = tokens.findByTokenHash(Hashes.sha256(raw)).orElseThrow();
        token.setExpiresAt(Instant.now().minusSeconds(30));
        tokens.save(token);
        mvc.perform(post("/reset-password").with(csrf())
                        .param("token", raw)
                        .param("password", "Next#Horse2026")
                        .param("passwordConfirm", "Next#Horse2026"))
                .andExpect(status().isOk());
        mvc.perform(post("/login").with(csrf()).param("username", email).param("password", PASSWORD))
                .andExpect(redirectedUrl("/"));

        mvc.perform(post("/forgot-password").with(csrf()).with(remote("reset2-" + email)).param("email", email));
        String fresh = tokenFrom(email);
        mvc.perform(post("/reset-password").with(csrf())
                        .param("token", fresh)
                        .param("password", "Next#Horse2026")
                        .param("passwordConfirm", "Next#Horse2026"))
                .andExpect(redirectedUrl("/login?reset"));
        mvc.perform(post("/reset-password").with(csrf())
                        .param("token", fresh)
                        .param("password", "Third#Horse2026")
                        .param("passwordConfirm", "Third#Horse2026"))
                .andExpect(status().isOk());
        mvc.perform(get("/").cookie(session)).andExpect(status().is3xxRedirection());
        mvc.perform(post("/login").with(csrf()).param("username", email).param("password", "Next#Horse2026"))
                .andExpect(redirectedUrl("/"));
    }

    @Test
    void commonPasswordAndEmailInsidePasswordAreRejected() throws Exception {
        mvc.perform(post("/registration").with(csrf()).with(remote("common"))
                        .param("email", email("common"))
                        .param("fullName", "Hoc Vien")
                        .param("password", "password123456")
                        .param("passwordConfirm", "password123456"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("phổ biến")));
        mvc.perform(post("/registration").with(csrf()).with(remote("contains"))
                        .param("email", "alice01@example.com")
                        .param("fullName", "Hoc Vien")
                        .param("password", "alice01#Secret1")
                        .param("passwordConfirm", "alice01#Secret1"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("email")));
    }

    @Test
    void passwordHistoryRejectsRecentPasswords() throws Exception {
        String email = activeStudent();
        Long id = users.findByUsername(email).orElseThrow().getId();
        String[] next = {"First#Horse2026", "Second#Horse2026", "Third#Horse2026", "Fourth#Horse2026", "Fifth#Horse2026"};
        String current = PASSWORD;
        for (String value : next) {
            userService.changePassword(id, current, value, "no-session");
            current = value;
        }
        Cookie session = login(email, current);
        mvc.perform(post("/account/password").cookie(session).with(csrf())
                        .param("currentPassword", current)
                        .param("password", PASSWORD)
                        .param("passwordConfirm", PASSWORD))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("5 mật khẩu")));
    }

    @Test
    void fiveWrongPasswordsLockTheAccountWithoutRevealingIt() throws Exception {
        String email = activeStudent();
        for (int i = 0; i < 5; i++) {
            mvc.perform(post("/login").with(csrf()).param("username", email).param("password", "Wrong#Horse2026"))
                    .andExpect(redirectedUrl("/login?error"));
        }
        mvc.perform(post("/login").with(csrf()).param("username", "nobody-" + UUID.randomUUID() + "@example.com")
                        .param("password", "Wrong#Horse2026"))
                .andExpect(redirectedUrl("/login?error"));
        assertThat(users.findByUsername(email).orElseThrow().getStatus()).isEqualTo(AccountStatus.LOCKED);
        mvc.perform(post("/login").with(csrf()).param("username", email).param("password", PASSWORD))
                .andExpect(redirectedUrl("/login?error"))
                .andExpect(unauthenticated());
        AppUser locked = users.findByUsername(email).orElseThrow();
        locked.setLockedUntil(Instant.now().minusSeconds(5));
        users.save(locked);
        mvc.perform(post("/login").with(csrf()).param("username", email).param("password", PASSWORD))
                .andExpect(redirectedUrl("/"))
                .andExpect(authenticated().withUsername(email));
    }

    @Test
    void loginTimingDoesNotRevealUnknownUsers() throws Exception {
        String known = activeStudent();
        for (int i = 0; i < 3; i++) {
            elapsedLogin(known);
            elapsedLogin("warmup-" + i + "@example.com");
        }
        List<Long> knownTimes = new ArrayList<>();
        List<Long> unknownTimes = new ArrayList<>();
        for (int i = 0; i < 9; i++) {
            knownTimes.add(elapsedLogin(known));
            unknownTimes.add(elapsedLogin("missing-" + UUID.randomUUID() + "@example.com"));
        }
        assertThat(Math.abs(median(knownTimes) - median(unknownTimes))).isLessThanOrEqualTo(50);
    }

    @Test
    void wrongTotpIsRejectedAndRecoveryCodeIsOneTime() throws Exception {
        String email = activeStudent();
        Cookie session = login(email, PASSWORD);
        String html = mvc.perform(get("/account/2fa/setup").cookie(session)).andReturn().getResponse().getContentAsString();
        String secret = extract(html, "totp-secret");
        assertThat(users.findByUsername(email).orElseThrow().getTotpSecret()).doesNotContain(secret);
        String wrong = wrongCode(secret);
        mvc.perform(post("/account/2fa/confirm").cookie(session).with(csrf()).param("code", wrong))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("không đúng")));
        assertThat(users.findByUsername(email).orElseThrow().isTotpEnabled()).isFalse();
        MvcResult confirmed = mvc.perform(post("/account/2fa/confirm").cookie(session).with(csrf())
                        .param("code", Totp.codeAt(secret, Instant.now())))
                .andExpect(status().isOk())
                .andReturn();
        @SuppressWarnings("unchecked")
        List<String> recoveryCodes = (List<String>) confirmed.getModelAndView().getModel().get("recoveryCodes");
        assertThat(recoveryCodes).hasSize(10);
        String code = recoveryCodes.getFirst();
        mvc.perform(post("/logout").cookie(session).with(csrf()));
        Cookie pending = passwordLogin(email, PASSWORD, "/2fa");
        mvc.perform(post("/2fa").cookie(pending).with(csrf()).param("code", wrongCode(secret)))
                .andExpect(redirectedUrl("/2fa?error"));
        MvcResult verified = mvc.perform(post("/2fa").cookie(pending).with(csrf()).param("code", code))
                .andExpect(redirectedUrl("/"))
                .andReturn();
        Cookie signedIn = verified.getResponse().getCookie("SESSION");
        mvc.perform(post("/logout").cookie(signedIn != null ? signedIn : pending).with(csrf()));
        Cookie again = passwordLogin(email, PASSWORD, "/2fa");
        mvc.perform(post("/2fa").cookie(again).with(csrf()).param("code", code))
                .andExpect(redirectedUrl("/2fa?error"));
    }

    @Test
    void lecturerMustEnrollTotpBeforeUsingThePortal() throws Exception {
        Cookie admin = adminSession();
        String email = email("lecturer");
        mvc.perform(post("/admin/users/invite").cookie(admin).with(csrf())
                        .param("email", email)
                        .param("fullName", "Giang Vien")
                        .param("role", "ROLE_LECTURER"))
                .andExpect(redirectedUrl("/admin/users"));
        String token = tokenFrom(email);
        mvc.perform(post("/reset-password").with(csrf())
                        .param("token", token)
                        .param("password", PASSWORD)
                        .param("passwordConfirm", PASSWORD))
                .andExpect(redirectedUrl("/login?reset"));
        Cookie session = passwordLogin(email, PASSWORD, "/account/2fa/setup");
        mvc.perform(get("/lecturer/students").cookie(session))
                .andExpect(redirectedUrl("/account/2fa/setup"));
        mvc.perform(get("/admin/users").cookie(login(activeStudent(), PASSWORD)))
                .andExpect(status().isForbidden());
    }

    @Test
    void rememberMeIsRevokedWhenPasswordChanges() throws Exception {
        String email = activeStudent();
        MvcResult login = mvc.perform(post("/login").with(csrf())
                        .param("username", email)
                        .param("password", PASSWORD)
                        .param("remember-me", "true"))
                .andExpect(redirectedUrl("/"))
                .andReturn();
        var cookie = login.getResponse().getCookie("remember-me");
        assertThat(cookie).isNotNull();
        assertThat(cookie.isHttpOnly()).isTrue();
        MvcResult home = mvc.perform(get("/").cookie(cookie)).andExpect(status().isOk()).andReturn();
        Cookie session = login.getResponse().getCookie("SESSION");
        assertThat(session).isNotNull();
        Cookie current = home.getResponse().getCookie("remember-me");
        mvc.perform(post("/account/password").cookie(session).with(csrf())
                        .param("currentPassword", PASSWORD)
                        .param("password", "Changed#Horse2026")
                        .param("passwordConfirm", "Changed#Horse2026"))
                .andExpect(redirectedUrl("/account/password?changed"));
        mvc.perform(get("/").cookie(current != null ? current : cookie)).andExpect(status().is3xxRedirection());
    }

    @Test
    void sessionsShowClientInfoAndChangingPasswordKeepsOnlyCurrentSession() throws Exception {
        String email = activeStudent();
        Cookie first = login(email, PASSWORD, "BrowserOne/1.0");
        Cookie second = login(email, PASSWORD, "BrowserTwo/2.0");
        mvc.perform(get("/account/sessions").cookie(second))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("BrowserTwo/2.0")));
        mvc.perform(post("/account/password").cookie(second).with(csrf())
                        .param("currentPassword", PASSWORD)
                        .param("password", "Session#Horse2026")
                        .param("passwordConfirm", "Session#Horse2026"))
                .andExpect(redirectedUrl("/account/password?changed"));
        mvc.perform(get("/").cookie(first)).andExpect(status().is3xxRedirection());
        mvc.perform(get("/").cookie(second)).andExpect(status().isOk());
    }

    @Test
    void atMostTwoConcurrentSessionsAreKept() throws Exception {
        String email = activeStudent();
        Cookie first = login(email, PASSWORD);
        Cookie second = login(email, PASSWORD);
        Cookie third = login(email, PASSWORD);
        mvc.perform(get("/").cookie(first)).andExpect(status().is3xxRedirection());
        mvc.perform(get("/").cookie(third)).andExpect(status().isOk());
        mvc.perform(get("/").cookie(second)).andExpect(status().isOk());
    }

    @Test
    void legacyPasswordHashIsUpgradedOnLogin() throws Exception {
        String email = email("legacy");
        AppUser user = new AppUser(email, "{noop}" + PASSWORD);
        user.setFullName("Legacy");
        user.setStatus(AccountStatus.ACTIVE);
        user.setEnabled(true);
        user.getRoles().add(roles.findByName(Role.STUDENT).orElseThrow());
        users.saveAndFlush(user);
        mvc.perform(post("/login").with(csrf()).param("username", email).param("password", PASSWORD))
                .andExpect(redirectedUrl("/"))
                .andExpect(authenticated().withUsername(email));
        assertThat(users.findByUsername(email).orElseThrow().getPasswordHash()).startsWith("{bcrypt}");
    }

    @Test
    void registrationIsLimitedToTenPerIpEachHour() throws Exception {
        String ip = "192.0.2.10";
        for (int i = 0; i < 10; i++) {
            mvc.perform(post("/registration").with(csrf()).with(remote(ip))
                            .param("email", "rate" + i + "-" + UUID.randomUUID() + "@example.com")
                            .param("fullName", "Hoc Vien")
                            .param("password", PASSWORD)
                            .param("passwordConfirm", PASSWORD))
                    .andExpect(redirectedUrl("/login?registered"));
        }
        mvc.perform(post("/registration").with(csrf()).with(remote(ip))
                        .param("email", email("rate-blocked"))
                        .param("fullName", "Hoc Vien")
                        .param("password", PASSWORD)
                        .param("passwordConfirm", PASSWORD))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("quá nhiều lần")));
    }

    @Test
    void postWithoutCsrfTokenIsForbidden() throws Exception {
        mvc.perform(post("/registration").param("email", email("csrf")))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(roles = "USER")
    void regularUserCannotOpenAdminArea() throws Exception {
        mvc.perform(get("/admin/users")).andExpect(status().isForbidden());
    }

    @Test
    void adminCanSearchAndCannotRemoveTheLastAdmin() throws Exception {
        String student = activeStudent();
        Cookie admin = adminSession();
        Long adminId = users.findByUsername(ADMIN_EMAIL).orElseThrow().getId();
        mvc.perform(get("/admin/users").cookie(admin).param("email", student).param("role", "ROLE_STUDENT").param("status", "ACTIVE"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString(student)));
        mvc.perform(post("/admin/users/" + adminId + "/delete").cookie(admin).with(csrf()).param("confirm", "true"))
                .andExpect(redirectedUrl("/admin/users/" + adminId))
                .andExpect(flash().attribute("error", org.hamcrest.Matchers.containsString("quản trị viên")));
        assertThat(users.findByUsername(ADMIN_EMAIL).orElseThrow().getStatus()).isEqualTo(AccountStatus.ACTIVE);

        String second = email("admin2");
        mvc.perform(post("/admin/users/invite").cookie(admin).with(csrf())
                        .param("email", second).param("fullName", "Admin Hai").param("role", "ROLE_ADMIN"))
                .andExpect(redirectedUrl("/admin/users"));
        mvc.perform(post("/reset-password").with(csrf())
                        .param("token", tokenFrom(second))
                        .param("password", PASSWORD)
                        .param("passwordConfirm", PASSWORD))
                .andExpect(redirectedUrl("/login?reset"));
        mvc.perform(post("/admin/users/" + adminId + "/role").cookie(admin).with(csrf()).param("role", "ROLE_STUDENT"))
                .andExpect(flash().attribute("error", org.hamcrest.Matchers.containsString("chính mình")));
        assertThat(users.findWithRolesByUsername(ADMIN_EMAIL).orElseThrow().hasRole(Role.ADMIN)).isTrue();
    }

    @Test
    void auditLogRecordsLoginFailuresWithoutPasswords() throws Exception {
        String email = activeStudent();
        mvc.perform(post("/login").with(csrf())
                        .header("User-Agent", "AuditBrowser/9")
                        .with(remote("203.0.113.10"))
                        .param("username", email)
                        .param("password", "Wrong#Horse2026"))
                .andExpect(redirectedUrl("/login?error"));
        var event = audit.search(AuditEventType.LOGIN_FAILURE, email, org.springframework.data.domain.PageRequest.of(0, 5))
                .getContent().getFirst();
        assertThat(event.getIp()).isEqualTo("203.0.113.10");
        assertThat(event.getUserAgent()).contains("AuditBrowser/9");
        assertThat(event.getDetails()).doesNotContain("Wrong#Horse2026");
        Cookie admin = adminSession();
        mvc.perform(get("/admin/audit").cookie(admin).param("type", "LOGIN_FAILURE").param("actor", email))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString(email)))
                .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("Wrong#Horse2026"))));
    }

    private String activeStudent() throws Exception {
        String email = email("stu");
        register(email);
        mvc.perform(get("/verify-email").param("token", tokenFrom(email)))
                .andExpect(redirectedUrl("/login?verified"));
        return email;
    }

    private void register(String email) throws Exception {
        mvc.perform(post("/registration").with(csrf()).with(remote(email))
                        .param("email", email)
                        .param("fullName", "Hoc Vien")
                        .param("password", PASSWORD)
                        .param("passwordConfirm", PASSWORD))
                .andExpect(redirectedUrl("/login?registered"));
    }

    private Cookie login(String email, String password) throws Exception {
        return login(email, password, "TestBrowser/1.0");
    }

    private Cookie login(String email, String password, String userAgent) throws Exception {
        MvcResult result = mvc.perform(post("/login").with(csrf())
                        .header("User-Agent", userAgent)
                        .param("username", email)
                        .param("password", password))
                .andExpect(redirectedUrl("/"))
                .andReturn();
        return sessionCookie(result);
    }

    private Cookie passwordLogin(String email, String password, String expectedRedirect) throws Exception {
        MvcResult result = mvc.perform(post("/login").with(csrf())
                        .param("username", email)
                        .param("password", password))
                .andExpect(redirectedUrl(expectedRedirect))
                .andReturn();
        return sessionCookie(result);
    }

    private Cookie sessionCookie(MvcResult result) {
        Cookie cookie = result.getResponse().getCookie("SESSION");
        assertThat(cookie).isNotNull();
        return cookie;
    }

    private Cookie adminSession() throws Exception {
        if (adminSecret == null) {
            Cookie session = passwordLogin(ADMIN_EMAIL, ADMIN_PASSWORD, "/account/2fa/setup");
            String html = mvc.perform(get("/account/2fa/setup").cookie(session)).andReturn().getResponse().getContentAsString();
            adminSecret = extract(html, "totp-secret");
            mvc.perform(post("/account/2fa/confirm").cookie(session).with(csrf())
                            .param("code", Totp.codeAt(adminSecret, Instant.now())))
                    .andExpect(status().isOk());
            return session;
        }
        Cookie session = passwordLogin(ADMIN_EMAIL, ADMIN_PASSWORD, "/2fa");
        MvcResult verified = mvc.perform(post("/2fa").cookie(session).with(csrf())
                        .param("code", Totp.codeAt(adminSecret, Instant.now())))
                .andExpect(redirectedUrl("/"))
                .andReturn();
        Cookie rotated = verified.getResponse().getCookie("SESSION");
        return rotated != null ? rotated : session;
    }

    private String tokenFrom(String email) {
        var message = mail.latestTo(email);
        assertThat(message).isNotNull();
        Matcher matcher = Pattern.compile("token=([A-Za-z0-9_\\-]+)").matcher(message.text());
        assertThat(matcher.find()).isTrue();
        return matcher.group(1);
    }

    private static String extract(String html, String id) {
        Matcher matcher = Pattern.compile("id=\"" + id + "\">([^<]+)").matcher(html);
        assertThat(matcher.find()).isTrue();
        return matcher.group(1);
    }

    private static String wrongCode(String secret) {
        String current = Totp.codeAt(secret, Instant.now());
        String candidate = "000000";
        if (candidate.equals(current)) {
            candidate = "111111";
        }
        return candidate;
    }

    private static String email(String prefix) {
        return prefix + "-" + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
    }

    private static RequestPostProcessor remote(String key) {
        int bucket = Math.floorMod(key.hashCode(), 180);
        String ip = key.startsWith("192.0.2.") || key.chars().filter(ch -> ch == '.').count() == 3 && key.startsWith("203.")
                ? key : "10.8." + (bucket / 50) + "." + (bucket % 50 + 1);
        if ("192.0.2.10".equals(key) || "203.0.113.10".equals(key)) {
            ip = key;
        }
        String address = ip;
        return request -> {
            request.setRemoteAddr(address);
            return request;
        };
    }

    private long elapsedLogin(String email) throws Exception {
        long start = System.nanoTime();
        mvc.perform(post("/login").with(csrf()).param("username", email).param("password", "Wrong#Horse2026"));
        return (System.nanoTime() - start) / 1_000_000;
    }

    private static long median(List<Long> values) {
        List<Long> sorted = values.stream().sorted(Comparator.naturalOrder()).toList();
        return sorted.get(sorted.size() / 2);
    }
}
