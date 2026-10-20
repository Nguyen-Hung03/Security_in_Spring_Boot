package com.fptaptech.auth.account;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

@Entity
@Table(name = "login_attempts")
public class LoginAttempt {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 254)
    private String username;

    @Column(nullable = false)
    private boolean success;

    @Column(nullable = false, length = 20)
    private String kind;

    @Column(name = "attempted_at", nullable = false)
    private Instant attemptedAt;

    protected LoginAttempt() {
    }

    public LoginAttempt(String username, boolean success, String kind, Instant attemptedAt) {
        this.username = username;
        this.success = success;
        this.kind = kind;
        this.attemptedAt = attemptedAt;
    }
}
