package com.emerson.identity.identity_service.controllers.dtos;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;

@AllArgsConstructor
@Getter
@Setter
@Builder
public class RsaKeyPairDto {
    private String id;
    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;
    private Instant createdAt;
}
