package com.emerson.identity.identity_service.entities.mfa;

import com.emerson.identity.identity_service.entities.enums.MultiFactorCodeStatus;
import com.emerson.identity.identity_service.entities.user.User;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table (name = "temporary_email_codes")
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@ToString
@Builder
public class TemporaryEmailCode {
    @Id
    @GeneratedValue (strategy = GenerationType.IDENTITY)
    private long id;

    private String code;

    private Instant issuedAt;

    private Instant expiresAt;

    @Enumerated(value = EnumType.ORDINAL)
    private MultiFactorCodeStatus multiFactorCodeStatus;

    @ManyToOne(targetEntity = User.class,fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", referencedColumnName = "userId")
    private User user;

}
