package com.emerson.identity.identity_service.repositories;

import com.emerson.identity.identity_service.entities.mfa.TemporaryEmailCode;
import io.lettuce.core.dynamic.annotation.Param;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface JpaTemporaryEmailCodeRepository extends JpaRepository<TemporaryEmailCode, Long> {

    @Query("SELECT t FROM temporary_email_codes WHERE t.user.id =:userId ORDER BY t.issuedAt DESC")
    List<TemporaryEmailCode> findByUserDescLimit1(@Param("userId") Long userId);

    void deleteAllByUser(Long userId);
}
