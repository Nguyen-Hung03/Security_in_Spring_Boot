package com.fptaptech.auth.account;

import org.springframework.data.jpa.repository.JpaRepository;
import java.time.Instant;

public interface LoginAttemptRepository extends JpaRepository<LoginAttempt, Long> {

    long countByUsernameAndSuccessFalseAndKindAndAttemptedAtAfter(
            String username, String kind, Instant attemptedAt);

    void deleteByAttemptedAtBefore(Instant cutoff);
}
