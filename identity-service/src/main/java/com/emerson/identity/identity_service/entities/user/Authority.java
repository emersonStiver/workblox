package com.emerson.identity.identity_service.entities.user;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "authorities")
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@ToString
@Builder
public class Authority {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long authorityId;

    @Column(name = "authority_name")
    private String authorityName; //Ex: READ_PRIVILEGES, WRITE_PRIVILEGES

}
