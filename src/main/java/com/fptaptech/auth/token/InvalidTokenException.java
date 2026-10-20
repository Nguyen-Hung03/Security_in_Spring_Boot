package com.fptaptech.auth.token;

public class InvalidTokenException extends RuntimeException {

    public InvalidTokenException() {
        super("Link không hợp lệ hoặc đã hết hạn");
    }
}
