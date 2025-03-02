package com.emerson.identity.identity_service.controllers.validators;

import org.springframework.validation.Validator;

public interface DynamicValidator extends Validator {
    Class<?> getSupportedClass();
}
