package com.fptaptech.auth.ratelimit;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import java.time.Duration;
import java.time.Instant;

@Service
public class RateLimitService {

    private final RateLimitRepository events;

    public RateLimitService(RateLimitRepository events) {
        this.events = events;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public boolean tryAcquire(String ip, String action, int limit, Duration window) {
        Instant now = Instant.now();
        events.deleteByOccurredAtBefore(now.minus(Duration.ofHours(2)));
        String key = ip == null || ip.isBlank() ? "unknown" : ip;
        long count = events.countByIpAndActionAndOccurredAtAfter(key, action, now.minus(window));
        if (count >= limit) {
            return false;
        }
        events.save(new RateLimitEvent(key, action, now));
        return true;
    }
}
