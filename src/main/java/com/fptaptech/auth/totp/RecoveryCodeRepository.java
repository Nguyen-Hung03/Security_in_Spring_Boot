package com.fptaptech.auth.totp;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface RecoveryCodeRepository extends JpaRepository<RecoveryCode, Long> {

    Optional<RecoveryCode> findByUserIdAndCodeHashAndUsedAtIsNull(Long userId, String codeHash);

    void deleteByUserId(Long userId);
}
