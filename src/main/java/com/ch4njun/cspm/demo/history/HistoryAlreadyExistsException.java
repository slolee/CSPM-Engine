package com.ch4njun.cspm.demo.history;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class HistoryAlreadyExistsException extends RuntimeException {
    public HistoryAlreadyExistsException(String message) {
        super(message);
    }
}
