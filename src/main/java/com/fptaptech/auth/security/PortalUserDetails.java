package com.fptaptech.auth.security;

import com.fptaptech.auth.user.AppUser;
import com.fptaptech.auth.user.Role;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import java.io.Serial;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public final class PortalUserDetails implements UserDetails {

    @Serial
    private static final long serialVersionUID = 1L;

    private final Long id;
    private final String email;
    private final String fullName;
    private final String passwordHash;
    private final boolean totpEnabled;
    private final boolean mustEnrollTotp;
    private final List<GrantedAuthority> authorities;

    private PortalUserDetails(Long id, String email, String fullName, String passwordHash,
                              boolean totpEnabled, boolean mustEnrollTotp, List<GrantedAuthority> authorities) {
        this.id = id;
        this.email = email;
        this.fullName = fullName;
        this.passwordHash = passwordHash;
        this.totpEnabled = totpEnabled;
        this.mustEnrollTotp = mustEnrollTotp;
        this.authorities = authorities;
    }

    public static PortalUserDetails from(AppUser user) {
        boolean staff = user.hasRole(Role.LECTURER) || user.hasRole(Role.ADMIN);
        List<GrantedAuthority> authorities = user.getRoles().stream()
                .map(role -> (GrantedAuthority) new SimpleGrantedAuthority(role.getName()))
                .toList();
        return new PortalUserDetails(
                user.getId(),
                user.getEmail(),
                user.getFullName(),
                user.getPasswordHash(),
                user.isTotpEnabled(),
                staff && !user.isTotpEnabled(),
                authorities);
    }

    public Long getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    public String getFullName() {
        return fullName;
    }

    public boolean isTotpEnabled() {
        return totpEnabled;
    }

    public boolean mustEnrollTotp() {
        return mustEnrollTotp;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return new ArrayList<>(authorities);
    }

    @Override
    public String getPassword() {
        return passwordHash;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public String toString() {
        return email;
    }
}
