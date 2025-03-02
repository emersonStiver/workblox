package com.emerson.identity.identity_service.entities.user;

import jakarta.persistence.*;
import lombok.*;

import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "roles")
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@ToString
@Builder
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long roleId;

    @Column(name = "role_name")
    private String roleName; // ROLE_ADMIN, ROLE_USER

    @ManyToMany( fetch = FetchType.EAGER )
    @JoinTable(
            name = "role_authorities",
            joinColumns = @JoinColumn(name = "role_id", referencedColumnName = "roleId"),
            inverseJoinColumns = @JoinColumn(name = "authority_id", referencedColumnName = "authorityId")
    )
    private Set<Authority> authorities = new HashSet<>();


}
