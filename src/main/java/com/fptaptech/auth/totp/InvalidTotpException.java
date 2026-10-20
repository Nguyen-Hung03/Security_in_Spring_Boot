package com.fptaptech.auth.totp;

public class InvalidTotpException extends RuntimeException {

    public InvalidTotpException() {
        super("Mã xác thực không đúng");
    }
}
