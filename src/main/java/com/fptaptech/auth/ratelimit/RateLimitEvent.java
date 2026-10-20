package com.fptaptech.auth.ratelimit;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

@Entity
@Table(name = "rate_limits")
public class RateLimitEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 45)
    private String ip;

    @Column(nullable = false, length = 40)
    private String action;

    @Column(name = "occurred_at", nullable = false)
    private Instant occurredAt;

    protected RateLimitEvent() {
    }

    public RateLimitEvent(String ip, String action, Instant occurredAt) {
        this.ip = ip;
        this.action = action;
        this.occurredAt = occurredAt;
    }
}
