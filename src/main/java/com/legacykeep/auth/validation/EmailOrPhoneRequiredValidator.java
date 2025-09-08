package com.legacykeep.auth.validation;

import com.legacykeep.auth.dto.RegisterRequestDto;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.springframework.util.StringUtils;

/**
 * Validator for EmailOrPhoneRequired annotation.
 * Ensures that either email or phone number is provided in the registration request.
 */
public class EmailOrPhoneRequiredValidator implements ConstraintValidator<EmailOrPhoneRequired, RegisterRequestDto> {

    @Override
    public void initialize(EmailOrPhoneRequired constraintAnnotation) {
        // No initialization needed
    }

    @Override
    public boolean isValid(RegisterRequestDto request, ConstraintValidatorContext context) {
        if (request == null) {
            return false;
        }

        boolean hasEmail = StringUtils.hasText(request.getEmail());
        boolean hasPhone = StringUtils.hasText(request.getPhoneNumber());

        // At least one of email or phone number must be provided
        return hasEmail || hasPhone;
    }
}