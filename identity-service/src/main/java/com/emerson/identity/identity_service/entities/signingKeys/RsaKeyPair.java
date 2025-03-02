package com.emerson.identity.identity_service.entities.signingKeys;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table (name = "rsa_keys")
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@ToString
@Builder
public class RsaKeyPair {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Instant createdAt;

    @Lob
    @Column(name = "rsa_private_key", columnDefinition = "text")
    private String rsaPrivateKey;

    @Lob
    @Column(name = "rsa_public_key", columnDefinition = "text")
    private String rsaPublicKey;

}

