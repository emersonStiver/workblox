package com.emerson.identity.identity_service.repositories;

import com.emerson.identity.identity_service.entities.mfa.QrCodeSecret;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface JpaQRCodeSecretRepository extends JpaRepository<QrCodeSecret, Long> {
    Optional<QrCodeSecret> findByUser(Long user);
}
