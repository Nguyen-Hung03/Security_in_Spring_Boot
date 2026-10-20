package com.fptaptech.auth.audit;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

@Entity
@Table(name = "audit_events")
public class AuditEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "occurred_at", nullable = false)
    private Instant occurredAt;

    @Enumerated(EnumType.STRING)
    @Column(name = "event_type", nullable = false, length = 40)
    private AuditEventType type;

    @Column(name = "actor_username", length = 254)
    private String actorUsername;

    @Column(name = "target_username", length = 254)
    private String targetUsername;

    @Column(length = 45)
    private String ip;

    @Column(name = "user_agent", length = 512)
    private String userAgent;

    @Column(length = 500)
    private String details;

    protected AuditEvent() {
    }

    public AuditEvent(Instant occurredAt, AuditEventType type, String actorUsername, String targetUsername,
                      String ip, String userAgent, String details) {
        this.occurredAt = occurredAt;
        this.type = type;
        this.actorUsername = actorUsername;
        this.targetUsername = targetUsername;
        this.ip = ip;
        this.userAgent = userAgent;
        this.details = details;
    }

    public Long getId() {
        return id;
    }

    public Instant getOccurredAt() {
        return occurredAt;
    }

    public AuditEventType getType() {
        return type;
    }

    public String getActorUsername() {
        return actorUsername;
    }

    public String getTargetUsername() {
        return targetUsername;
    }

    public String getIp() {
        return ip;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public String getDetails() {
        return details;
    }
}
