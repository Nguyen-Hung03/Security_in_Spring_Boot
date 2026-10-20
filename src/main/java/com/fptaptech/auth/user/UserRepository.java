package com.fptaptech.auth.user;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import java.util.Optional;

public interface UserRepository extends JpaRepository<AppUser, Long> {

    Optional<AppUser> findByUsername(String username);

    boolean existsByUsername(String username);

    @EntityGraph(attributePaths = "roles")
    @Query("select u from AppUser u where u.username = :username")
    Optional<AppUser> findWithRolesByUsername(@Param("username") String username);

    @EntityGraph(attributePaths = "roles")
    @Query("select u from AppUser u where u.id = :id")
    Optional<AppUser> findWithRolesById(@Param("id") Long id);

    @Query("""
            select count(u) from AppUser u join u.roles r
            where r.name = :role and u.status = :status
            """)
    long countByRoleAndStatus(@Param("role") String role, @Param("status") AccountStatus status);

    @EntityGraph(attributePaths = "roles")
    @Query("""
            select distinct u from AppUser u
            where (:email is null or lower(u.email) like lower(concat('%', :email, '%')))
            and (:status is null or u.status = :status)
            and (:role is null or exists (select 1 from u.roles r where r.name = :role))
            """)
    Page<AppUser> search(@Param("email") String email,
                         @Param("status") AccountStatus status,
                         @Param("role") String role,
                         Pageable pageable);

    @EntityGraph(attributePaths = "roles")
    @Query("select u from AppUser u join u.roles r where r.name = :role")
    Page<AppUser> findByRoleName(@Param("role") String role, Pageable pageable);
}
