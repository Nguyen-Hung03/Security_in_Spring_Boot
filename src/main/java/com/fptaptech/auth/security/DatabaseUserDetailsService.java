package com.fptaptech.auth.security;

import com.fptaptech.auth.user.AccountStatus;
import com.fptaptech.auth.user.UserRepository;
import com.fptaptech.auth.user.UserService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class DatabaseUserDetailsService implements UserDetailsService {

    private final UserRepository users;

    public DatabaseUserDetailsService(UserRepository users) {
        this.users = users;
    }

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) {
        return users.findWithRolesByUsername(UserService.normalize(username))
                .filter(user -> user.getStatus() == AccountStatus.ACTIVE)
                .map(PortalUserDetails::from)
                .orElseThrow(() -> new UsernameNotFoundException("Không tìm thấy tài khoản"));
    }
}
