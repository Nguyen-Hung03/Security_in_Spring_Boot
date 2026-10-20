package com.fptaptech.auth.web;

import com.fptaptech.auth.account.LockoutService;
import com.fptaptech.auth.audit.AuditEventType;
import com.fptaptech.auth.audit.AuditService;
import com.fptaptech.auth.security.PortalAuthenticationProvider;
import com.fptaptech.auth.security.PortalUserDetails;
import com.fptaptech.auth.security.Requests;
import com.fptaptech.auth.totp.InvalidTotpException;
import com.fptaptech.auth.totp.TotpService;
import com.fptaptech.auth.user.AccountStatus;
import com.fptaptech.auth.user.AdminRuleException;
import com.fptaptech.auth.user.UserService;
import com.fptaptech.auth.user.WeakPasswordException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import java.util.List;

@Controller
public class TotpController {

    private final TotpService totpService;
    private final UserService userService;
    private final LockoutService lockout;
    private final AuditService audit;
    private final SecurityContextRepository securityContexts = new HttpSessionSecurityContextRepository();

    public TotpController(TotpService totpService, UserService userService, LockoutService lockout, AuditService audit) {
        this.totpService = totpService;
        this.userService = userService;
        this.lockout = lockout;
        this.audit = audit;
    }

    @GetMapping("/2fa")
    String challenge(Authentication authentication, Model model) {
        if (!pending(authentication)) {
            return "redirect:/login";
        }
        model.addAttribute("error", false);
        return "totp-challenge";
    }

    @PostMapping("/2fa")
    String submitChallenge(@RequestParam String code, Authentication authentication, HttpServletRequest request,
                           HttpServletResponse response) {
        if (!pending(authentication) || !(authentication.getPrincipal() instanceof PortalUserDetails details)) {
            return "redirect:/login";
        }
        try {
            totpService.verifyLogin(details.getId(), code);
        } catch (InvalidTotpException ex) {
            lockout.recordFailure(details.getEmail(), LockoutService.TOTP, request);
            var snapshot = userService.loadSnapshot(details.getEmail());
            if (snapshot != null && snapshot.status() == AccountStatus.LOCKED) {
                SecurityContextHolder.clearContext();
                HttpSession session = request.getSession(false);
                if (session != null) {
                    session.invalidate();
                }
                return "redirect:/login?error";
            }
            return "redirect:/2fa?error";
        }
        request.changeSessionId();
        HttpSession session = request.getSession();
        session.setAttribute("TOTP_OK", Boolean.TRUE);
        PortalUserDetails refreshed = userService.loadDetails(details.getEmail());
        var completed = UsernamePasswordAuthenticationToken.authenticated(refreshed, null, refreshed.getAuthorities());
        var context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(completed);
        SecurityContextHolder.setContext(context);
        securityContexts.saveContext(context, request, response);
        audit.record(AuditEventType.LOGIN_SUCCESS, refreshed.getEmail(), refreshed.getEmail(), request, "Đăng nhập với xác thực hai bước");
        return "redirect:/";
    }

    @GetMapping("/account/2fa/setup")
    String setup(Authentication authentication, HttpServletResponse response, Model model) {
        PortalUserDetails details = current(authentication);
        response.setHeader("Cache-Control", "no-store");
        model.addAttribute("enabled", details.isTotpEnabled());
        model.addAttribute("mandatory", details.mustEnrollTotp() || staff(details));
        if (!details.isTotpEnabled()) {
            String secret = totpService.ensurePendingSecret(details.getId());
            model.addAttribute("secret", secret);
            model.addAttribute("qr", totpService.qrDataUri(details.getEmail(), secret));
        }
        return "totp-setup";
    }

    @PostMapping("/account/2fa/confirm")
    String confirm(@RequestParam String code, Authentication authentication, HttpServletRequest request,
                   HttpServletResponse response, Model model) {
        PortalUserDetails details = current(authentication);
        response.setHeader("Cache-Control", "no-store");
        try {
            List<String> codes = totpService.confirm(details.getId(), code);
            refresh(userService.loadDetails(details.getEmail()), request, response);
            model.addAttribute("recoveryCodes", codes);
            return "totp-recovery";
        } catch (InvalidTotpException ex) {
            model.addAttribute("enabled", false);
            model.addAttribute("mandatory", details.mustEnrollTotp() || staff(details));
            model.addAttribute("confirmError", true);
            String secret = totpService.ensurePendingSecret(details.getId());
            model.addAttribute("secret", secret);
            model.addAttribute("qr", totpService.qrDataUri(details.getEmail(), secret));
            return "totp-setup";
        }
    }

    @PostMapping("/account/2fa/disable")
    String disable(@RequestParam String password, @RequestParam String code, Authentication authentication,
                   HttpServletRequest request, HttpServletResponse response, Model model) {
        PortalUserDetails details = current(authentication);
        try {
            totpService.disable(details.getId(), password, code);
            refresh(userService.loadDetails(details.getEmail()), request, response);
        } catch (RuntimeException ex) {
            model.addAttribute("actionError", ex.getMessage());
            model.addAttribute("enabled", true);
            model.addAttribute("mandatory", staff(details));
            return "totp-setup";
        }
        return "redirect:/account/2fa/setup?disabled";
    }

    @PostMapping("/account/2fa/recovery")
    String regenerate(@RequestParam String password, @RequestParam String code, Authentication authentication,
                      HttpServletResponse response, Model model) {
        PortalUserDetails details = current(authentication);
        response.setHeader("Cache-Control", "no-store");
        try {
            model.addAttribute("recoveryCodes", totpService.regenerateRecoveryCodes(details.getId(), password, code));
            return "totp-recovery";
        } catch (InvalidTotpException | WeakPasswordException | AdminRuleException ex) {
            model.addAttribute("actionError", ex.getMessage());
            model.addAttribute("enabled", details.isTotpEnabled());
            model.addAttribute("mandatory", staff(details));
            return "totp-setup";
        }
    }

    private void refresh(PortalUserDetails details, HttpServletRequest request, HttpServletResponse response) {
        var authentication = UsernamePasswordAuthenticationToken.authenticated(details, null, details.getAuthorities());
        var context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
        securityContexts.saveContext(context, request, response);
        if (request.getSession(false) != null) {
            request.getSession().setAttribute("TOTP_OK", Boolean.TRUE);
        }
    }

    private boolean pending(Authentication authentication) {
        return authentication != null && authentication.getAuthorities().stream()
                .anyMatch(authority -> PortalAuthenticationProvider.PENDING_AUTHORITY.equals(authority.getAuthority()));
    }

    private boolean staff(PortalUserDetails details) {
        return details.getAuthorities().stream().anyMatch(authority ->
                "ROLE_LECTURER".equals(authority.getAuthority()) || "ROLE_ADMIN".equals(authority.getAuthority()));
    }

    private PortalUserDetails current(Authentication authentication) {
        if (authentication != null && authentication.getPrincipal() instanceof PortalUserDetails details) {
            return details;
        }
        throw new org.springframework.security.access.AccessDeniedException("Cần đăng nhập");
    }
}
