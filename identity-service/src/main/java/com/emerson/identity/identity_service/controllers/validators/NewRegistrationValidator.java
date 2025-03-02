package com.emerson.identity.identity_service.controllers.validators;

import com.emerson.identity.identity_service.controllers.dtos.NewRegistrationDto;
import org.springframework.validation.Errors;

public class NewRegistrationValidator implements DynamicValidator{

    @Override
    public Class<?> getSupportedClass( ){
        return NewRegistrationDto.class;
    }

    @Override
    public boolean supports(Class<?> clazz){
        return NewRegistrationDto.class.isAssignableFrom(clazz);
    }

    @Override
    public void validate(Object target, Errors errors){

    }
}
