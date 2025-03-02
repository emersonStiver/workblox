package com.emerson.identity.identity_service.security;

import com.emerson.identity.identity_service.entities.user.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import java.util.Collection;
import java.util.stream.Collectors;

public class UserSecurityDetails implements UserDetails {
    private User user;
    public UserSecurityDetails(User user){
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities( ){
        return this.user.getRoles().stream()
                .flatMap(role ->
                         role
                        .getAuthorities()
                            .stream()
                            .map(authority -> new SimpleGrantedAuthority(authority.getAuthorityName()))
                ).collect(Collectors.toSet());
    }

    @Override
    public String getPassword( ){
        return this.getPassword();
    }

    @Override
    public String getUsername( ){
        return this.getUsername();
    }

    @Override
    public boolean isEnabled(){
        return this.user.isEnabled();
    }

    @Override
    public boolean isCredentialsNonExpired(){
        return this.user.isCredentialsNonExpired();
    }

    @Override
    public boolean isAccountNonLocked(){
        return this.user.isAccountNonLocked();
    }

    @Override
    public boolean isAccountNonExpired(){
        return this.user.isAccountNonExpired();
    }

    public User getUser(){
        return User.builder()
                .email(this.user.getEmail())
                .password("PROTECTED")
                .roles(this.user.getRoles())
                .isAccountNonExpired(this.user.isAccountNonExpired())
                .isAccountNonLocked(this.user.isAccountNonLocked())
                .isEnabled(this.user.isEnabled())
                .isCredentialsNonExpired(this.user.isCredentialsNonExpired())

                .createdAt(this.user.getCreatedAt())
                .updatedAt(this.user.getUpdatedAt())
                .build();
    }
}
