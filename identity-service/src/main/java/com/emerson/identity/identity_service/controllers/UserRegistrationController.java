package com.emerson.identity.identity_service.controllers;

import com.emerson.identity.identity_service.controllers.dtos.EmailAvailabilityDto;
import com.emerson.identity.identity_service.controllers.dtos.NewRegistrationDto;
import com.emerson.identity.identity_service.controllers.validators.CompositeValidator;
import com.emerson.identity.identity_service.security.NewUserDetails;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(value = "/registration")
@AllArgsConstructor
@Slf4j
public class UserRegistrationController {

    private final UserDetailsManager userDetailsManagerImp;
    private final CompositeValidator compositeValidator;

    @InitBinder
    public void loadValidator(WebDataBinder webDataBinder){webDataBinder.addValidators(compositeValidator);}

    @GetMapping("/emailAvailability")
    public ResponseEntity<ApiResponse<EmailAvailabilityDto>> checkEmailAvailability(@RequestParam("email") @Valid String email, BindingResult result){
        log.info("Checking availability for email: {}", email);
        boolean isTaken = userDetailsManagerImp.userExists(email);
        return ResponseEntity
                .ok(ApiResponse
                        .success(EmailAvailabilityDto
                                .builder()
                                .email(email)
                                .isTaken(isTaken)
                                .build()
                        )
                );
    }

    @PostMapping("/newUser")
    public ResponseEntity<ApiResponse<NewRegistrationDto>> registerNewUser(@Valid @RequestBody NewRegistrationDto newRegistrationDto, BindingResult result){
        userDetailsManagerImp.createUser(NewUserDetails.builder().newRegistrationDto(newRegistrationDto).build());
        return null;
    }



}
