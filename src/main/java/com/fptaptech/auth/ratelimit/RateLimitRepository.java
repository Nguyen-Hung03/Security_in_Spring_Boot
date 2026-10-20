package com.fptaptech.auth.ratelimit;

import org.springframework.data.jpa.repository.JpaRepository;
import java.time.Instant;

public interface RateLimitRepository extends JpaRepository<RateLimitEvent, Long> {

    long countByIpAndActionAndOccurredAtAfter(String ip, String action, Instant occurredAt);

    void deleteByOccurredAtBefore(Instant cutoff);
}
