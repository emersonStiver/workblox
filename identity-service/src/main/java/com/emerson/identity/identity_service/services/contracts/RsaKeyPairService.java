package com.emerson.identity.identity_service.services.contracts;

import com.emerson.identity.identity_service.controllers.dtos.RsaKeyPairDto;

import java.util.List;

public interface RsaKeyPairService {
    List<RsaKeyPairDto> getAllRsaKeyPairs();
    void rotateSigningKeys();
    void deleteRsaKeyPair(String id);
    boolean isRsaKeyPairInitialized();
}
