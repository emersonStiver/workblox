package com.emerson.identity.identity_service.controllers;

import com.emerson.identity.identity_service.services.contracts.RsaKeyPairService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/admin")
@RequiredArgsConstructor
public class AdminController {

    private final RsaKeyPairService rsaKeyPairService;

    @PostMapping("/oauth2/rotate-keys")
    public String rotateKeys(){
        rsaKeyPairService.rotateSigningKeys();
        return "Test";
    }

}

