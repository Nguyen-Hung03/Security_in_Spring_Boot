package com.fptaptech.auth.mail;

public interface EmailGateway {

    void send(String to, String subject, String text);
}
