package com.fptaptech.auth.audit;

import com.fptaptech.auth.security.ClientInfo;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import java.time.Instant;

@Service
public class AuditService {

    private final AuditRepository events;

    public AuditService(AuditRepository events) {
        this.events = events;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void record(AuditEventType type, String actor, String target, HttpServletRequest request, String details) {
        String safeDetails = details == null ? null : (details.length() > 500 ? details.substring(0, 500) : details);
        events.save(new AuditEvent(
                Instant.now(),
                type,
                trim(actor, 254),
                trim(target, 254),
                ClientInfo.ip(request),
                ClientInfo.userAgent(request),
                safeDetails));
    }

    private static String trim(String value, int max) {
        if (value == null) {
            return null;
        }
        return value.length() > max ? value.substring(0, max) : value;
    }
}
