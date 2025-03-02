package com.emerson.identity.identity_service.controllers.validators;

import com.emerson.identity.identity_service.controllers.dtos.EmailAvailabilityDto;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
@Component
public class EmailAvailabilityValidator implements DynamicValidator {

    @Override
    public Class<?> getSupportedClass(){
        return EmailAvailabilityDto.class;
    }

    @Override
    public boolean supports(Class<?> clazz){
        return EmailAvailabilityDto.class.isAssignableFrom(clazz);
    }

    @Override
    public void validate(Object target, Errors errors){
        if (target instanceof EmailAvailabilityDto dto) {
            if (dto.getEmail() == null || !dto.getEmail().matches("^[A-Za-z0-9+_.-]+@(.+)$")) {
                errors.rejectValue("email", "Invalid.email", "Invalid email format");
            }
        }
    }
}
