package com.ch4njun.cspm.demo.assessment;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.NOT_FOUND)
public class AssessmentResultNotFoundException extends RuntimeException {
    public AssessmentResultNotFoundException(String message) {
        super(message);
    }
}
