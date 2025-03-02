package com.emerson.identity.identity_service.security;

import com.emerson.identity.identity_service.controllers.dtos.NewRegistrationDto;
import lombok.Builder;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Builder
public class NewUserDetails implements UserDetails {
    private NewRegistrationDto newRegistrationDto;
    private NewUserDetails(NewRegistrationDto newRegistrationDto){
        this.newRegistrationDto = newRegistrationDto;
    }
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities(){
        return List.of();
    }

    @Override
    public String getPassword( ){
        return this.newRegistrationDto.getPassword();
    }

    @Override
    public String getUsername( ){
        return this.newRegistrationDto.getEmail();
    }

    public String getName(){
        return this.newRegistrationDto.getName();
    }
    public String getLastName(){
        return this.newRegistrationDto.getLastName();
    }
}
