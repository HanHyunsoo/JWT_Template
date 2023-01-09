package com.jwt.common.exception.auth;

import com.jwt.common.exception.CustomAbstractException;
import com.jwt.common.response.StatusEnum;

public class LoginFailedException extends CustomAbstractException {
    public LoginFailedException() {
        super(StatusEnum.LOGIN_FAILED);
    }
}
