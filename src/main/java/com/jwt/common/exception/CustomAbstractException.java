package com.jwt.common.exception;

import com.jwt.common.response.StatusEnum;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public abstract class CustomAbstractException extends RuntimeException {

    protected final StatusEnum statusEnum;
}
