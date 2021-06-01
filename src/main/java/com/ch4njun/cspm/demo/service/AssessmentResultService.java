package com.ch4njun.cspm.demo.service;

import com.ch4njun.cspm.demo.dto.AssessmentResultDto;
import com.ch4njun.cspm.demo.dto.MessageDto;

import java.util.Iterator;
import java.util.List;

public interface AssessmentResultService {
    MessageDto runAssessmentScript(AssessmentResultDto.Run runDto);
    List<AssessmentResultDto.Response> findAssessmentResults(AssessmentResultDto.GetRequest requestDto);
    AssessmentResultDto.Response findAssessmentResultById(int id);
    AssessmentResultDto.Response saveInterview(int id, AssessmentResultDto.PutRequest requestDto);
}
