package com.emerson.identity.identity_service.controllers.dtos;

import lombok.*;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@ToString
@Builder
public class MfaCodeSentDto {
    String code;
}
