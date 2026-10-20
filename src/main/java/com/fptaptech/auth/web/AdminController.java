package com.fptaptech.auth.web;

import com.fptaptech.auth.audit.AuditEventType;
import com.fptaptech.auth.audit.AuditRepository;
import com.fptaptech.auth.security.PortalUserDetails;
import com.fptaptech.auth.user.AccountStatus;
import com.fptaptech.auth.user.AdminRuleException;
import com.fptaptech.auth.user.AdminUserService;
import com.fptaptech.auth.user.UsernameAlreadyExistsException;
import jakarta.validation.Valid;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
public class AdminController {

    private final AdminUserService adminUsers;
    private final AuditRepository audit;

    public AdminController(AdminUserService adminUsers, AuditRepository audit) {
        this.adminUsers = adminUsers;
        this.audit = audit;
    }

    @GetMapping("/admin/users")
    String users(@RequestParam(required = false) String email,
                 @RequestParam(required = false) String role,
                 @RequestParam(required = false) String status,
                 @PageableDefault(size = 10, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable,
                 Model model) {
        AccountStatus parsed = parseStatus(status);
        model.addAttribute("users", adminUsers.search(email, parsed, role, pageable));
        model.addAttribute("email", email == null ? "" : email);
        model.addAttribute("role", role == null ? "" : role);
        model.addAttribute("status", status == null ? "" : status);
        model.addAttribute("statuses", AccountStatus.values());
        return "admin-users";
    }

    @GetMapping("/admin/users/invite")
    String inviteForm(Model model) {
        if (!model.containsAttribute("form")) {
            model.addAttribute("form", new InviteForm());
        }
        return "admin-invite";
    }

    @PostMapping("/admin/users/invite")
    String invite(@Valid @ModelAttribute("form") InviteForm form, BindingResult result, RedirectAttributes redirect) {
        if (result.hasErrors()) {
            return "admin-invite";
        }
        try {
            adminUsers.invite(form.getEmail(), form.getFullName(), form.getRole());
        } catch (UsernameAlreadyExistsException ex) {
            result.rejectValue("email", "registration.email.duplicate");
            return "admin-invite";
        }
        redirect.addFlashAttribute("success", "Đã gửi email mời đặt mật khẩu.");
        return "redirect:/admin/users";
    }

    @GetMapping("/admin/users/{id}")
    String detail(@PathVariable Long id, Model model) {
        model.addAttribute("user", adminUsers.get(id));
        return "admin-user";
    }

    @PostMapping("/admin/users/{id}/disable")
    String disable(@PathVariable Long id, Authentication authentication, RedirectAttributes redirect) {
        return act(id, redirect, () -> adminUsers.disable(current(authentication).getId(), id));
    }

    @PostMapping("/admin/users/{id}/enable")
    String enable(@PathVariable Long id, RedirectAttributes redirect) {
        return act(id, redirect, () -> adminUsers.enable(id));
    }

    @PostMapping("/admin/users/{id}/role")
    String role(@PathVariable Long id, @RequestParam String role, Authentication authentication, RedirectAttributes redirect) {
        return act(id, redirect, () -> adminUsers.changeRole(current(authentication).getId(), id, role));
    }

    @PostMapping("/admin/users/{id}/logout")
    String logout(@PathVariable Long id, RedirectAttributes redirect) {
        return act(id, redirect, () -> adminUsers.forceLogout(id));
    }

    @PostMapping("/admin/users/{id}/totp-reset")
    String resetTotp(@PathVariable Long id, RedirectAttributes redirect) {
        return act(id, redirect, () -> adminUsers.resetTotp(id));
    }

    @PostMapping("/admin/users/{id}/delete")
    String delete(@PathVariable Long id, @RequestParam(defaultValue = "false") boolean confirm,
                  Authentication authentication, RedirectAttributes redirect) {
        if (!confirm) {
            redirect.addFlashAttribute("error", "Hãy xác nhận trước khi xóa tài khoản.");
            return "redirect:/admin/users/" + id;
        }
        try {
            adminUsers.delete(current(authentication).getId(), id);
            redirect.addFlashAttribute("success", "Đã xóa tài khoản.");
            return "redirect:/admin/users";
        } catch (AdminRuleException ex) {
            redirect.addFlashAttribute("error", ex.getMessage());
            return "redirect:/admin/users/" + id;
        }
    }

    @GetMapping("/admin/audit")
    String auditLog(@RequestParam(required = false) String type,
                    @RequestParam(required = false) String actor,
                    @PageableDefault(size = 20, sort = "occurredAt", direction = Sort.Direction.DESC) Pageable pageable,
                    Model model) {
        AuditEventType parsed = null;
        if (type != null && !type.isBlank()) {
            try {
                parsed = AuditEventType.valueOf(type);
            } catch (IllegalArgumentException ignored) {
                parsed = null;
            }
        }
        String actorFilter = actor == null || actor.isBlank() ? null : actor.trim().replace("%", "").replace("_", "");
        model.addAttribute("events", audit.search(parsed, actorFilter, pageable));
        model.addAttribute("type", type == null ? "" : type);
        model.addAttribute("actor", actor == null ? "" : actor);
        model.addAttribute("types", AuditEventType.values());
        return "admin-audit";
    }

    private String act(Long id, RedirectAttributes redirect, Runnable action) {
        try {
            action.run();
            redirect.addFlashAttribute("success", "Đã cập nhật tài khoản.");
        } catch (AdminRuleException | IllegalArgumentException ex) {
            redirect.addFlashAttribute("error", ex.getMessage());
        }
        return "redirect:/admin/users/" + id;
    }

    private PortalUserDetails current(Authentication authentication) {
        if (authentication != null && authentication.getPrincipal() instanceof PortalUserDetails details) {
            return details;
        }
        throw new AccessDeniedException("Cần đăng nhập");
    }

    private AccountStatus parseStatus(String status) {
        if (status == null || status.isBlank()) {
            return null;
        }
        try {
            return AccountStatus.valueOf(status);
        } catch (IllegalArgumentException ex) {
            return null;
        }
    }
}
