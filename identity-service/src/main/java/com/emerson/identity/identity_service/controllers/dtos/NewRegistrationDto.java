package com.emerson.identity.identity_service.controllers.dtos;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@AllArgsConstructor
@Builder
@Getter
@Setter
public class NewRegistrationDto {
    private String name;
    private String lastName;
    private String email;
    private String password;
}
