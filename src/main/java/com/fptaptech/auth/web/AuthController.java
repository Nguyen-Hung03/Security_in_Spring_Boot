package com.fptaptech.auth.web;

import com.fptaptech.auth.ratelimit.RateLimitService;
import com.fptaptech.auth.security.ClientInfo;
import com.fptaptech.auth.security.PortalAuthenticationProvider;
import com.fptaptech.auth.security.PortalUserDetails;
import com.fptaptech.auth.token.InvalidTokenException;
import com.fptaptech.auth.user.UserService;
import com.fptaptech.auth.user.UsernameAlreadyExistsException;
import com.fptaptech.auth.user.WeakPasswordException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import java.time.Duration;

@Controller
public class AuthController {

    private final UserService userService;
    private final RateLimitService rateLimit;

    public AuthController(UserService userService, RateLimitService rateLimit) {
        this.userService = userService;
        this.rateLimit = rateLimit;
    }

    @GetMapping("/registration")
    String registrationForm(Authentication authentication, Model model) {
        if (isLoggedIn(authentication)) {
            return "redirect:/";
        }
        model.addAttribute("form", new RegistrationForm());
        return "registration";
    }

    @PostMapping("/registration")
    String register(@Valid @ModelAttribute("form") RegistrationForm form, BindingResult result,
                    HttpServletRequest request) {
        if (result.hasErrors()) {
            form.clearPasswords();
            return "registration";
        }
        if (!rateLimit.tryAcquire(ClientInfo.ip(request), "REGISTER", 10, Duration.ofHours(1))) {
            result.reject("rate.limit", "Bạn đã đăng ký quá nhiều lần từ mạng này. Thử lại sau.");
            form.clearPasswords();
            return "registration";
        }
        try {
            userService.register(form.getEmail(), form.getFullName(), form.getPassword());
        } catch (UsernameAlreadyExistsException ex) {
            result.rejectValue("email", "registration.email.duplicate");
            form.clearPasswords();
            return "registration";
        } catch (WeakPasswordException ex) {
            result.rejectValue("password", "password.weak", ex.getMessage());
            form.clearPasswords();
            return "registration";
        }
        return "redirect:/login?registered";
    }

    @GetMapping("/login")
    String login(Authentication authentication) {
        if (authentication == null || authentication instanceof AnonymousAuthenticationToken) {
            return "login";
        }
        boolean pending = authentication.getAuthorities().stream()
                .anyMatch(authority -> PortalAuthenticationProvider.PENDING_AUTHORITY.equals(authority.getAuthority()));
        if (pending) {
            return "redirect:/2fa";
        }
        if (authentication.getPrincipal() instanceof PortalUserDetails details && details.mustEnrollTotp()) {
            return "redirect:/account/2fa/setup";
        }
        return "redirect:/";
    }

    @GetMapping("/forgot-password")
    String forgotForm(Authentication authentication, Model model) {
        if (isLoggedIn(authentication)) {
            return "redirect:/";
        }
        model.addAttribute("form", new EmailForm());
        return "forgot-password";
    }

    @PostMapping("/forgot-password")
    String forgot(@Valid @ModelAttribute("form") EmailForm form, BindingResult result, HttpServletRequest request) {
        if (result.hasErrors()) {
            return "forgot-password";
        }
        if (rateLimit.tryAcquire(ClientInfo.ip(request), "FORGOT", 20, Duration.ofHours(1))) {
            userService.requestPasswordReset(form.getEmail());
        }
        return "redirect:/forgot-password/sent";
    }

    @GetMapping("/forgot-password/sent")
    String forgotSent() {
        return "forgot-sent";
    }

    @GetMapping("/reset-password")
    String resetForm(String token, Model model) {
        ResetPasswordForm form = new ResetPasswordForm();
        form.setToken(token == null ? "" : token);
        model.addAttribute("form", form);
        return "reset-password";
    }

    @PostMapping("/reset-password")
    String reset(@Valid @ModelAttribute("form") ResetPasswordForm form, BindingResult result) {
        if (result.hasErrors()) {
            form.clearPasswords();
            return "reset-password";
        }
        try {
            userService.completePasswordToken(form.getToken(), form.getPassword());
        } catch (InvalidTokenException ex) {
            result.reject("token.invalid", "Link không hợp lệ hoặc đã hết hạn");
            form.clearPasswords();
            return "reset-password";
        } catch (WeakPasswordException ex) {
            result.rejectValue("password", "password.weak", ex.getMessage());
            form.clearPasswords();
            return "reset-password";
        }
        return "redirect:/login?reset";
    }

    @GetMapping("/verify-email")
    String verify(String token) {
        try {
            userService.verifyEmail(token);
        } catch (InvalidTokenException ex) {
            return "redirect:/login?verifyError";
        }
        return "redirect:/login?verified";
    }

    @PostMapping("/verification/resend")
    String resend(@Valid @ModelAttribute("resend") EmailForm form, BindingResult result) {
        if (!result.hasErrors()) {
            userService.resendVerification(form.getEmail());
        }
        return "redirect:/login?resent";
    }

    private boolean isLoggedIn(Authentication authentication) {
        return authentication != null && !(authentication instanceof AnonymousAuthenticationToken);
    }
}
