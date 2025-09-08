package com.legacykeep.auth.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

/**
 * Custom validation annotation to ensure either email or phone number is provided.
 * This allows flexible registration where users can use either email or phone number.
 */
@Documented
@Constraint(validatedBy = EmailOrPhoneRequiredValidator.class)
@Target({ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface EmailOrPhoneRequired {
    
    String message() default "Either email or phone number must be provided";
    
    Class<?>[] groups() default {};
    
    Class<? extends Payload>[] payload() default {};
}