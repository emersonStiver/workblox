package com.emerson.identity.identity_service.entities.user;

import com.emerson.identity.identity_service.entities.enums.MFAMethod;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "users")
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@ToString
@Builder
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long userId; // Internal ID for database indexing

    @Column(unique = true, updatable = false, nullable = false)
    private UUID uuid = UUID.randomUUID(); // Public ID for external use

    private String names;
    private String lastNames;
    private String email;

    @Column(name = "hashed_password")
    private String password;

    @OneToOne(cascade = CascadeType.ALL, mappedBy = "userId")
    private PhoneNumber phoneNumber;

    @Column(name = "is_mfa_enabled", columnDefinition = "BOOLEAN DEFAULT false")
    private boolean isMultiFactorAuthenticationEnabled = false;

    private boolean isSecurityQuestionEnabled = false;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "user_mfa_methods", joinColumns = @JoinColumn(name = "user_id"))
    @Enumerated(EnumType.STRING)
    private List<MFAMethod> mfaMethods = new ArrayList<>();

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id", referencedColumnName = "userId"),
            inverseJoinColumns = @JoinColumn(name = "role_id", referencedColumnName = "roleId")
    )
    private Set<Role> roles;

    private boolean isAccountNonExpired = true;
    private boolean isEnabled = true;
    private boolean isAccountNonLocked = true;
    private boolean isCredentialsNonExpired = true;

    private Instant createdAt;
    private Instant updatedAt;
}
