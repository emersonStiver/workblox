package com.emerson.identity.identity_service.entities.user;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table (name = "phone_numbers")
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@ToString
@Builder
public class PhoneNumber {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    @OneToOne()
    @JoinColumn(name = "user_id", referencedColumnName = "userId")
    private User userId;

    @Column(name = "indicative", columnDefinition = "CHAR(2)")
    private String indicative;

    @Column(name = "phone_number", columnDefinition = "CHAR(10)")
    private String phoneNumber;

    private boolean isAuthenticated;
}
