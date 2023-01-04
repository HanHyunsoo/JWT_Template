package com.jwt.config;

import com.jwt.common.exception.CustomAbstractException;
import com.jwt.common.response.FailureResponseBody;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice(basePackages = "com")
public class GlobalExceptionHandler {

    @ExceptionHandler(CustomAbstractException.class)
    public ResponseEntity<FailureResponseBody> handelExceptions(CustomAbstractException e) {
        return FailureResponseBody.toResponseEntity(e.getStatusEnum());
    }
}
