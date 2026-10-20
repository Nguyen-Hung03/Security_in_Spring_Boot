package com.fptaptech.auth.user;

public class UsernameAlreadyExistsException extends RuntimeException {

    public UsernameAlreadyExistsException(String username) {
        super("Username đã tồn tại: " + username);
    }
}
