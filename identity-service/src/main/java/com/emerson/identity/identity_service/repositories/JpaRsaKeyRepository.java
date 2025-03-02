package com.emerson.identity.identity_service.repositories;

import com.emerson.identity.identity_service.entities.signingKeys.RsaKeyPair;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface JpaRsaKeyRepository extends JpaRepository<RsaKeyPair, Long> {

    List<RsaKeyPair> findAllOrderByCreatedAtDesc();
}
/*
    List<RsaKeyPair> findKeyPairs();
    void delete(String id);
    void save(RsaKeyPair rsaKeyPair);
 */