package com.fptaptech.auth.devices;

import com.fptaptech.auth.web.TimeFormat;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.stereotype.Service;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;

@Service
public class DeviceSessionService {

    public static final String LOGIN_IP = "LOGIN_IP";
    public static final String LOGIN_UA = "LOGIN_UA";
    public static final String LOGIN_AT = "LOGIN_AT";
    public static final String ACCOUNT_EMAIL = "ACCOUNT_EMAIL";

    private final FindByIndexNameSessionRepository<Session> sessions;

    @SuppressWarnings("unchecked")
    public DeviceSessionService(FindByIndexNameSessionRepository<? extends Session> sessions) {
        this.sessions = (FindByIndexNameSessionRepository<Session>) sessions;
    }

    public List<DeviceView> list(String email, String currentSessionId) {
        return sessions.findByPrincipalName(email).entrySet().stream()
                .filter(entry -> !entry.getValue().isExpired())
                .map(entry -> toView(entry.getKey(), entry.getValue(), currentSessionId))
                .sorted(Comparator.comparing(DeviceView::loggedInAt).reversed())
                .toList();
    }

    public void revoke(String email, String sessionId) {
        if (!sessions.findByPrincipalName(email).containsKey(sessionId)) {
            return;
        }
        sessions.deleteById(sessionId);
    }

    public void revokeOthers(String email, String currentSessionId) {
        sessions.findByPrincipalName(email).keySet().stream()
                .filter(id -> !id.equals(currentSessionId))
                .forEach(sessions::deleteById);
    }

    public void revokeAll(String email) {
        sessions.findByPrincipalName(email).keySet().forEach(sessions::deleteById);
    }

    private DeviceView toView(String id, Session session, String currentSessionId) {
        Object loggedAt = session.getAttribute(LOGIN_AT);
        String formatted = "";
        if (loggedAt instanceof String text && !text.isBlank()) {
            formatted = TimeFormat.format(Instant.parse(text));
        }
        Object ip = session.getAttribute(LOGIN_IP);
        Object agent = session.getAttribute(LOGIN_UA);
        return new DeviceView(id, formatted, ip == null ? "" : ip.toString(), agent == null ? "" : agent.toString(),
                id.equals(currentSessionId));
    }

}
