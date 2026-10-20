package com.fptaptech.auth.config;

import com.fptaptech.auth.audit.AuditService;
import com.fptaptech.auth.security.AuditLogoutHandler;
import com.fptaptech.auth.security.DatabaseUserDetailsService;
import com.fptaptech.auth.security.LoginFailureHandler;
import com.fptaptech.auth.security.LoginSuccessHandler;
import com.fptaptech.auth.security.PortalAuthenticationProvider;
import com.fptaptech.auth.security.TotpEnrollmentFilter;
import com.fptaptech.auth.security.TwoFactorRememberMeFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.RememberMeAuthenticationProvider;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenBasedRememberMeServices;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.session.security.SpringSessionBackedSessionRegistry;
import org.springframework.security.core.session.SessionRegistry;
import javax.sql.DataSource;
import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private static final String CSP = "default-src 'self'; script-src 'self'; style-src 'self' https://cdn.jsdelivr.net; "
            + "img-src 'self' data:; font-src 'self' https://cdn.jsdelivr.net; form-action 'self'; "
            + "frame-ancestors 'none'; base-uri 'self'; object-src 'none'";

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, PortalAuthenticationProvider provider,
                                             DatabaseUserDetailsService userDetailsService,
                                             PersistentTokenRepository tokenRepository, SessionRegistry sessionRegistry,
                                             AuditService audit, AppProperties properties, Environment environment)
            throws Exception {
        AuthenticationManager authenticationManager = new ProviderManager(List.of(
                provider, new RememberMeAuthenticationProvider(properties.getRememberMeKey())));
        RememberMeServices rememberMeServices = rememberMeServices(properties, userDetailsService, tokenRepository);
        http.authenticationManager(authenticationManager)
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers("/registration", "/login", "/error", "/forgot-password", "/forgot-password/sent",
                            "/reset-password", "/verify-email", "/verification/resend").permitAll();
                    if (environment.acceptsProfiles(Profiles.of("test"))) {
                        auth.requestMatchers("/test/**").permitAll();
                    }
                    auth.requestMatchers("/2fa").hasAuthority(PortalAuthenticationProvider.PENDING_AUTHORITY)
                            .requestMatchers("/admin/**").hasRole("ADMIN")
                            .requestMatchers("/lecturer/**").hasAnyRole("LECTURER", "ADMIN")
                            .requestMatchers(HttpMethod.GET, "/").authenticated()
                            .anyRequest().access((authentication, context) -> {
                                Authentication current = authentication.get();
                                boolean pending = current != null && current.getAuthorities().stream()
                                        .anyMatch(authority -> PortalAuthenticationProvider.PENDING_AUTHORITY.equals(authority.getAuthority()));
                                boolean allowed = current != null && current.isAuthenticated() && !pending;
                                return new AuthorizationDecision(allowed);
                            });
                })
                .formLogin(form -> form
                        .loginPage("/login")
                        .successHandler(new LoginSuccessHandler(audit))
                        .failureHandler(new LoginFailureHandler())
                        .permitAll())
                .logout(logout -> logout
                        .logoutSuccessUrl("/login?logout")
                        .addLogoutHandler(new AuditLogoutHandler(audit))
                        .permitAll())
                .rememberMe(remember -> remember.rememberMeServices(rememberMeServices))
                .sessionManagement(session -> {
                    session.sessionFixation(fixation -> fixation.changeSessionId());
                    session.maximumSessions(2)
                            .expiredUrl("/login?expired")
                            .sessionRegistry(sessionRegistry);
                })
                .headers(headers -> {
                    headers.contentSecurityPolicy(csp -> csp.policyDirectives(CSP));
                    headers.referrerPolicy(referrer -> referrer.policy(ReferrerPolicy.NO_REFERRER));
                    headers.frameOptions(frame -> frame.deny());
                    if (properties.isProduction()) {
                        headers.httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(31_536_000));
                    } else {
                        headers.httpStrictTransportSecurity(hsts -> hsts.disable());
                    }
                })
                .addFilterAfter(new TwoFactorRememberMeFilter(), RememberMeAuthenticationFilter.class)
                .addFilterAfter(new TotpEnrollmentFilter(), AuthorizationFilter.class);
        return http.build();
    }

    @Bean
    PersistentTokenRepository persistentTokenRepository(DataSource dataSource) {
        JdbcTokenRepositoryImpl repository = new JdbcTokenRepositoryImpl();
        repository.setDataSource(dataSource);
        return repository;
    }

    @Bean
    @SuppressWarnings({"rawtypes", "unchecked"})
    SessionRegistry sessionRegistry(FindByIndexNameSessionRepository<? extends Session> sessionRepository) {
        return new SpringSessionBackedSessionRegistry(sessionRepository);
    }

    private static RememberMeServices rememberMeServices(AppProperties properties, DatabaseUserDetailsService users,
                                                         PersistentTokenRepository tokenRepository) {
        PersistentTokenBasedRememberMeServices services = new PersistentTokenBasedRememberMeServices(
                properties.getRememberMeKey(), users, tokenRepository);
        services.setTokenValiditySeconds(14 * 24 * 60 * 60);
        services.setUseSecureCookie(properties.isProduction());
        services.setCookieCustomizer(cookie -> {
            cookie.setHttpOnly(true);
            cookie.setSecure(properties.isProduction());
            cookie.setAttribute("SameSite", "Lax");
        });
        return services;
    }
}
