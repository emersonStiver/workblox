package com.emerson.identity.identity_service.repositories;

import com.emerson.identity.identity_service.entities.oauth2.RegisteredClientEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface JpaRegisteredClientRepository extends JpaRepository<RegisteredClientEntity, String> {

    Optional<RegisteredClientEntity> findByClientId(String clientId);
}
