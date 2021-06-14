package com.ch4njun.cspm.demo.controller;

import com.ch4njun.cspm.demo.dto.AssessmentResultDto;
import com.ch4njun.cspm.demo.service.AssessmentResultService;
import com.ch4njun.cspm.demo.dto.MessageDto;
import com.ch4njun.cspm.demo.repository.HistoryRepository;
import com.ch4njun.cspm.demo.model.AssessmentResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("/assessment-results")
public class AssessmentResultController {
    @Autowired
    private AssessmentResultService assessmentResultService;

    @GetMapping("")
    @CrossOrigin(origins = "*", allowedHeaders = "*")
    public ResponseEntity<List<AssessmentResultDto.Response>> retrieveAssessmentResults(@RequestParam(required = false) String historyId,
                                                                           @RequestParam(required = false) String resourceId,
                                                                           @RequestParam(required = false) String result) {
        AssessmentResultDto.GetRequest requestDto = new AssessmentResultDto.GetRequest(historyId, resourceId, result);
        List<AssessmentResultDto.Response> assessmentResults = assessmentResultService.findAssessmentResults(requestDto);

        return new ResponseEntity<>(assessmentResults, HttpStatus.OK);
    }

    @GetMapping("/{id}")
    @CrossOrigin(origins = "*", allowedHeaders = "*")
    public ResponseEntity<AssessmentResultDto.Response> retrieveAssessmentResult(@PathVariable int id) {
        AssessmentResultDto.Response responseDto = assessmentResultService.findAssessmentResultById(id);
        return new ResponseEntity<>(responseDto, HttpStatus.OK);
    }

    @PostMapping("")
    @CrossOrigin(origins = "*", allowedHeaders = "*")
    public ResponseEntity<MessageDto> run(@RequestBody AssessmentResultDto.Run runDto) {
        MessageDto messageDto = assessmentResultService.runAssessmentScript(runDto);
        return new ResponseEntity<>(messageDto, HttpStatus.CREATED);
    }

    @PutMapping("/{id}")
    @CrossOrigin(origins = "*", allowedHeaders = "*")
    public ResponseEntity<AssessmentResultDto.Response> interview(@PathVariable int id, @RequestBody AssessmentResultDto.PutRequest requestDto) {
        AssessmentResultDto.Response responseDto = assessmentResultService.saveInterview(id, requestDto);
        return new ResponseEntity<>(responseDto, HttpStatus.CREATED);
    }
}
