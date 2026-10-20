package com.fptaptech.auth.web;

import com.fptaptech.auth.audit.AuditEventType;
import com.fptaptech.auth.audit.AuditService;
import com.fptaptech.auth.devices.DeviceSessionService;
import com.fptaptech.auth.security.PortalUserDetails;
import com.fptaptech.auth.user.UserRepository;
import com.fptaptech.auth.user.UserService;
import com.fptaptech.auth.user.WeakPasswordException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class AccountController {

    private final UserService userService;
    private final UserRepository users;
    private final DeviceSessionService devices;
    private final AuditService audit;

    public AccountController(UserService userService, UserRepository users, DeviceSessionService devices, AuditService audit) {
        this.userService = userService;
        this.users = users;
        this.devices = devices;
        this.audit = audit;
    }

    @GetMapping("/")
    String welcome() {
        return "welcome";
    }

    @GetMapping("/account/profile")
    String profile(Authentication authentication, Model model) {
        PortalUserDetails details = current(authentication);
        var user = users.findById(details.getId()).orElseThrow();
        ProfileForm form = new ProfileForm();
        form.setFullName(user.getFullName());
        form.setPhone(user.getPhone() == null ? "" : user.getPhone());
        model.addAttribute("form", form);
        model.addAttribute("email", user.getEmail());
        return "profile";
    }

    @PostMapping("/account/profile")
    String updateProfile(@Valid @ModelAttribute("form") ProfileForm form, BindingResult result,
                         Authentication authentication, Model model) {
        PortalUserDetails details = current(authentication);
        model.addAttribute("email", details.getEmail());
        if (result.hasErrors()) {
            return "profile";
        }
        userService.updateProfile(details.getId(), form.getFullName(), form.getPhone());
        model.addAttribute("saved", true);
        return "profile";
    }

    @GetMapping("/account/password")
    String passwordForm(Model model) {
        model.addAttribute("form", new ChangePasswordForm());
        return "change-password";
    }

    @PostMapping("/account/password")
    String changePassword(@Valid @ModelAttribute("form") ChangePasswordForm form, BindingResult result,
                          Authentication authentication, HttpServletRequest request) {
        if (result.hasErrors()) {
            form.clearPasswords();
            return "change-password";
        }
        PortalUserDetails details = current(authentication);
        try {
            String sessionId = request.getSession(false) == null ? "" : request.getSession().getId();
            userService.changePassword(details.getId(), form.getCurrentPassword(), form.getPassword(), sessionId);
        } catch (WeakPasswordException ex) {
            result.rejectValue(ex.getMessage().contains("hiện tại") ? "currentPassword" : "password",
                    "password.weak", ex.getMessage());
            form.clearPasswords();
            return "change-password";
        }
        return "redirect:/account/password?changed";
    }

    @GetMapping("/account/sessions")
    String sessions(Authentication authentication, HttpServletRequest request, Model model) {
        PortalUserDetails details = current(authentication);
        String sessionId = request.getSession(false) == null ? "" : request.getSession().getId();
        model.addAttribute("devices", devices.list(details.getEmail(), sessionId));
        return "sessions";
    }

    @PostMapping("/account/sessions/{id}/revoke")
    String revoke(@PathVariable String id, Authentication authentication, HttpServletRequest request) {
        PortalUserDetails details = current(authentication);
        String currentId = request.getSession(false) == null ? "" : request.getSession().getId();
        devices.revoke(details.getEmail(), id);
        audit.record(AuditEventType.SESSION_REVOKED, details.getEmail(), details.getEmail(), request, "Đăng xuất một thiết bị");
        if (id.equals(currentId)) {
            return "redirect:/login?logout";
        }
        return "redirect:/account/sessions";
    }

    private PortalUserDetails current(Authentication authentication) {
        if (authentication != null && authentication.getPrincipal() instanceof PortalUserDetails details) {
            return details;
        }
        throw new AccessDeniedException("Cần đăng nhập");
    }
}
