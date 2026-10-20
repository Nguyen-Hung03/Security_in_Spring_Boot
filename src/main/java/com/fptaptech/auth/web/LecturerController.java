package com.fptaptech.auth.web;

import com.fptaptech.auth.user.AdminUserService;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LecturerController {

    private final AdminUserService adminUsers;

    public LecturerController(AdminUserService adminUsers) {
        this.adminUsers = adminUsers;
    }

    @GetMapping("/lecturer/students")
    String students(@PageableDefault(size = 10, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable,
                    Model model) {
        model.addAttribute("users", adminUsers.students(pageable));
        return "students";
    }
}
