package com.emerson.identity.identity_service.repositories;

import com.emerson.identity.identity_service.entities.user.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface JpaUserDetailsRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);

    boolean existByEmail(String email);
}
