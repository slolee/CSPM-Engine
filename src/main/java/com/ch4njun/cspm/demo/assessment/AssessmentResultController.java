package com.ch4njun.cspm.demo.assessment;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AssessmentResultController {
    @Autowired
    private AssessmentResultRepository assessmentResultRepository;

}