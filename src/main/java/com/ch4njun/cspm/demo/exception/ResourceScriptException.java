package com.ch4njun.cspm.demo.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
public class ResourceScriptException extends RuntimeException {
    public ResourceScriptException(String message) {
        super(message);
    }
}
