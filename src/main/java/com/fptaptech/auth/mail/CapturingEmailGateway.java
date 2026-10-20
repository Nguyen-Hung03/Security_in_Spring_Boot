package com.fptaptech.auth.mail;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

@Component
@Profile("test")
public class CapturingEmailGateway implements EmailGateway {

    public record Captured(String to, String subject, String text) {
    }

    private final List<Captured> messages = new CopyOnWriteArrayList<>();

    @Override
    public void send(String to, String subject, String text) {
        messages.add(new Captured(to, subject, text));
    }

    public List<Captured> all() {
        return List.copyOf(messages);
    }

    public Captured latestTo(String email) {
        for (int i = messages.size() - 1; i >= 0; i--) {
            if (messages.get(i).to().equalsIgnoreCase(email)) {
                return messages.get(i);
            }
        }
        return null;
    }
}
