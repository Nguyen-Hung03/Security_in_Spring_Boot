package com.fptaptech.auth.audit;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface AuditRepository extends JpaRepository<AuditEvent, Long> {

    @Query("""
            select e from AuditEvent e
            where (:type is null or e.type = :type)
            and (:actor is null or lower(e.actorUsername) like lower(concat('%', :actor, '%'))
                or lower(e.targetUsername) like lower(concat('%', :actor, '%')))
            """)
    Page<AuditEvent> search(@Param("type") AuditEventType type, @Param("actor") String actor, Pageable pageable);
}
