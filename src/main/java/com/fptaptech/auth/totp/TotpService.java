package com.fptaptech.auth.totp;

import com.fptaptech.auth.audit.AuditEventType;
import com.fptaptech.auth.audit.AuditService;
import com.fptaptech.auth.security.Hashes;
import com.fptaptech.auth.security.Requests;
import com.fptaptech.auth.user.AdminRuleException;
import com.fptaptech.auth.user.AppUser;
import com.fptaptech.auth.user.Role;
import com.fptaptech.auth.user.UserRepository;
import com.fptaptech.auth.user.WeakPasswordException;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

@Service
public class TotpService {

    private static final String ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    private static final SecureRandom RANDOM = new SecureRandom();

    private final UserRepository users;
    private final RecoveryCodeRepository codes;
    private final CryptoService crypto;
    private final PasswordEncoder passwordEncoder;
    private final AuditService audit;

    public TotpService(UserRepository users, RecoveryCodeRepository codes, CryptoService crypto,
                       PasswordEncoder passwordEncoder, AuditService audit) {
        this.users = users;
        this.codes = codes;
        this.crypto = crypto;
        this.passwordEncoder = passwordEncoder;
        this.audit = audit;
    }

    @Transactional
    public String ensurePendingSecret(Long userId) {
        AppUser user = users.findById(userId).orElseThrow();
        if (user.isTotpEnabled()) {
            return null;
        }
        if (user.getTotpSecret() != null) {
            return crypto.decrypt(user.getTotpSecret());
        }
        return storeNewSecret(user);
    }

    @Transactional
    public String replacePendingSecret(Long userId) {
        AppUser user = users.findById(userId).orElseThrow();
        if (user.isTotpEnabled()) {
            throw new IllegalStateException("Xác thực hai bước đang bật");
        }
        return storeNewSecret(user);
    }

    @Transactional
    public List<String> confirm(Long userId, String code) {
        AppUser user = users.findById(userId).orElseThrow();
        if (user.getTotpSecret() == null || !Totp.matches(crypto.decrypt(user.getTotpSecret()), code, Instant.now())) {
            throw new InvalidTotpException();
        }
        user.setTotpEnabled(true);
        List<String> recovery = replaceRecoveryCodes(user);
        audit.record(AuditEventType.TOTP_ENABLED, user.getEmail(), user.getEmail(), Requests.current(), "Bật xác thực hai bước");
        return recovery;
    }

    @Transactional
    public void verifyLogin(Long userId, String code) {
        AppUser user = users.findById(userId).orElseThrow();
        String normalized = code == null ? "" : code.trim();
        if (normalized.matches("\\d{6}") && user.getTotpSecret() != null
                && Totp.matches(crypto.decrypt(user.getTotpSecret()), normalized, Instant.now())) {
            return;
        }
        String compact = normalized.replace("-", "").replace(" ", "").toUpperCase(Locale.ROOT);
        if (compact.length() == 8) {
            var recovery = codes.findByUserIdAndCodeHashAndUsedAtIsNull(userId, Hashes.sha256(compact)).orElse(null);
            if (recovery != null) {
                recovery.setUsedAt(Instant.now());
                return;
            }
        }
        throw new InvalidTotpException();
    }

    @Transactional
    public void disable(Long userId, String password, String code) {
        AppUser user = users.findWithRolesById(userId).orElseThrow();
        if (user.hasRole(Role.LECTURER) || user.hasRole(Role.ADMIN)) {
            throw new AdminRuleException("Giảng viên và quản trị viên không được tắt xác thực hai bước");
        }
        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            throw new WeakPasswordException("Mật khẩu hiện tại không đúng");
        }
        if (!user.isTotpEnabled() || user.getTotpSecret() == null
                || !Totp.matches(crypto.decrypt(user.getTotpSecret()), code, Instant.now())) {
            throw new InvalidTotpException();
        }
        clear(user);
        audit.record(AuditEventType.TOTP_DISABLED, user.getEmail(), user.getEmail(), Requests.current(), "Tắt xác thực hai bước");
    }

    @Transactional
    public void adminReset(Long userId, String actorEmail) {
        AppUser user = users.findById(userId).orElseThrow();
        clear(user);
        audit.record(AuditEventType.TOTP_DISABLED, actorEmail, user.getEmail(), Requests.current(), "Quản trị tắt xác thực hai bước");
    }

    @Transactional
    public List<String> regenerateRecoveryCodes(Long userId, String password, String code) {
        AppUser user = users.findById(userId).orElseThrow();
        if (!user.isTotpEnabled()) {
            throw new InvalidTotpException();
        }
        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            throw new WeakPasswordException("Mật khẩu hiện tại không đúng");
        }
        verifyLogin(userId, code);
        return replaceRecoveryCodes(user);
    }

    public String qrDataUri(String email, String secret) {
        try {
            String label = URLEncoder.encode("FPT Aptech:" + email, StandardCharsets.UTF_8);
            String issuer = URLEncoder.encode("FPT Aptech", StandardCharsets.UTF_8);
            String url = "otpauth://totp/" + label + "?secret=" + secret + "&issuer=" + issuer + "&algorithm=SHA1&digits=6&period=30";
            BitMatrix matrix = new QRCodeWriter().encode(url, BarcodeFormat.QR_CODE, 240, 240);
            BufferedImage image = new BufferedImage(matrix.getWidth(), matrix.getHeight(), BufferedImage.TYPE_INT_RGB);
            for (int y = 0; y < matrix.getHeight(); y++) {
                for (int x = 0; x < matrix.getWidth(); x++) {
                    image.setRGB(x, y, matrix.get(x, y) ? 0x000000 : 0xFFFFFF);
                }
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ImageIO.write(image, "png", out);
            return "data:image/png;base64," + Base64.getEncoder().encodeToString(out.toByteArray());
        } catch (Exception ex) {
            throw new IllegalStateException("Không tạo được mã QR", ex);
        }
    }

    private String storeNewSecret(AppUser user) {
        String secret = Totp.randomSecret();
        user.setTotpSecret(crypto.encrypt(secret));
        user.setTotpEnabled(false);
        return secret;
    }

    private void clear(AppUser user) {
        user.setTotpEnabled(false);
        user.setTotpSecret(null);
        codes.deleteByUserId(user.getId());
    }

    private List<String> replaceRecoveryCodes(AppUser user) {
        codes.deleteByUserId(user.getId());
        List<String> rawCodes = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            String raw = randomGroup() + "-" + randomGroup();
            rawCodes.add(raw);
            codes.save(new RecoveryCode(user, Hashes.sha256(raw.replace("-", ""))));
        }
        return rawCodes;
    }

    private static String randomGroup() {
        StringBuilder group = new StringBuilder(4);
        for (int i = 0; i < 4; i++) {
            group.append(ALPHABET.charAt(RANDOM.nextInt(ALPHABET.length())));
        }
        return group.toString();
    }
}
