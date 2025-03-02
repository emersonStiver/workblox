package com.emerson.identity.identity_service.entities.mfa;

import com.emerson.identity.identity_service.entities.user.User;
import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "qrcode_secrets")
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@ToString
@Builder
public class QrCodeSecret {

    @Id
    @GeneratedValue (strategy = GenerationType.IDENTITY)
    private long id;

    private String secret;

    private String keyName;

    @Column(name = "is_enabled", columnDefinition = "default false")
    private boolean isEnabled;

    @Column(name = "is_registered", columnDefinition = "default false")
    private boolean isRegistered;

    @OneToOne
    @JoinColumn(name = "user_id", referencedColumnName = "userId", nullable = false, updatable = false, unique = true)
    private User user;
}
