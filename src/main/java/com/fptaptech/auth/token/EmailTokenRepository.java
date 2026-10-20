package com.fptaptech.auth.token;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import java.time.Instant;
import java.util.Optional;

public interface EmailTokenRepository extends JpaRepository<EmailToken, Long> {

    Optional<EmailToken> findByTokenHash(String tokenHash);

    long countByUserIdAndPurposeAndCreatedAtAfter(Long userId, EmailTokenPurpose purpose, Instant createdAt);

    @Modifying(flushAutomatically = true)
    @Query("""
            update EmailToken t set t.usedAt = :now
            where t.user.id = :userId and t.purpose = :purpose and t.usedAt is null and t.id <> :keepId
            """)
    void invalidateOthers(@Param("userId") Long userId,
                          @Param("purpose") EmailTokenPurpose purpose,
                          @Param("keepId") Long keepId,
                          @Param("now") Instant now);
}
