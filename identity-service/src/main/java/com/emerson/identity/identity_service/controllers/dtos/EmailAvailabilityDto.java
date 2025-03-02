package com.emerson.identity.identity_service.controllers.dtos;

import lombok.*;

@AllArgsConstructor
@Getter
@Setter
@ToString
@Builder
public class EmailAvailabilityDto {
    private String email;
    private boolean isTaken;
}
