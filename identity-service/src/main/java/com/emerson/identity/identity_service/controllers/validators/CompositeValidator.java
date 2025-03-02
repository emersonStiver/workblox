package com.emerson.identity.identity_service.controllers.validators;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
@Component
public class CompositeValidator implements Validator {

    private final Map<Class<?>, DynamicValidator> dynamicValidatorRegistry = new HashMap<>();

    @Autowired
    public CompositeValidator(List<DynamicValidator> dynamicValidators) {
        for(DynamicValidator dynamicValidator : dynamicValidators){
            if(dynamicValidator instanceof  DynamicValidator validator){
                dynamicValidatorRegistry.put(validator.getSupportedClass(), validator);
            }
        }
    }

    @Override
    public boolean supports(Class<?> clazz){
        return this.dynamicValidatorRegistry.containsKey(clazz);
    }

    @Override
    public void validate(Object target, Errors errors){
        DynamicValidator dynamicValidator = dynamicValidatorRegistry.get(target.getClass());
        if(dynamicValidator != null){
            dynamicValidator.validate(target, errors);
        }
    }

}
