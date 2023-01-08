package com.jwt.common.exception.auth;

import com.jwt.common.exception.CustomAbstractException;
import com.jwt.common.response.StatusEnum;

public class UsernameAlreadyExistsException extends CustomAbstractException {
    public UsernameAlreadyExistsException() {
        super(StatusEnum.USERNAME_ALREADY_EXISTS);
    }
}
