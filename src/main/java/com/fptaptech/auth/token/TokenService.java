package com.fptaptech.auth.token;

import com.fptaptech.auth.security.Hashes;
import com.fptaptech.auth.user.AppUser;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.EnumSet;
import java.util.Set;

@Service
public class TokenService {

    private final EmailTokenRepository tokens;
    private final SecureRandom random = new SecureRandom();

    public TokenService(EmailTokenRepository tokens) {
        this.tokens = tokens;
    }

    @Transactional
    public String issue(AppUser user, EmailTokenPurpose purpose, Duration ttl) {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        String raw = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        EmailToken token = new EmailToken();
        token.setUser(user);
        token.setTokenHash(Hashes.sha256(raw));
        token.setPurpose(purpose);
        token.setExpiresAt(Instant.now().plus(ttl));
        token.setCreatedAt(Instant.now());
        tokens.save(token);
        return raw;
    }

    @Transactional(readOnly = true)
    public EmailToken peek(String raw, Set<EmailTokenPurpose> allowed) {
        EmailToken token = load(raw);
        if (!allowed.contains(token.getPurpose()) || !usable(token)) {
            throw new InvalidTokenException();
        }
        return token;
    }

    @Transactional
    public EmailToken consume(String raw, Set<EmailTokenPurpose> allowed) {
        EmailToken token = load(raw);
        if (!allowed.contains(token.getPurpose()) || !usable(token)) {
            throw new InvalidTokenException();
        }
        token.setUsedAt(Instant.now());
        tokens.save(token);
        tokens.invalidateOthers(token.getUser().getId(), token.getPurpose(), token.getId(), Instant.now());
        return token;
    }

    public long recentCount(Long userId, EmailTokenPurpose purpose, Duration window) {
        return tokens.countByUserIdAndPurposeAndCreatedAtAfter(userId, purpose, Instant.now().minus(window));
    }

    private EmailToken load(String raw) {
        if (raw == null || raw.isBlank() || raw.length() > 200) {
            throw new InvalidTokenException();
        }
        return tokens.findByTokenHash(Hashes.sha256(raw)).orElseThrow(InvalidTokenException::new);
    }

    private boolean usable(EmailToken token) {
        return token.getUsedAt() == null && token.getExpiresAt().isAfter(Instant.now());
    }

    public static Set<EmailTokenPurpose> passwordPurposes() {
        return EnumSet.of(EmailTokenPurpose.PASSWORD_RESET, EmailTokenPurpose.INVITE);
    }
}
