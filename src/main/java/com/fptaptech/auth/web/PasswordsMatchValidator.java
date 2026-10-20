package com.fptaptech.auth.web;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import java.util.Objects;

public class PasswordsMatchValidator implements ConstraintValidator<PasswordsMatch, PasswordConfirmation> {

    @Override
    public boolean isValid(PasswordConfirmation form, ConstraintValidatorContext context) {
        if (form == null || form.getPassword() == null || form.getPasswordConfirm() == null) {
            return true;
        }
        if (Objects.equals(form.getPassword(), form.getPasswordConfirm())) {
            return true;
        }
        context.disableDefaultConstraintViolation();
        context.buildConstraintViolationWithTemplate(context.getDefaultConstraintMessageTemplate())
                .addPropertyNode("passwordConfirm")
                .addConstraintViolation();
        return false;
    }
}
