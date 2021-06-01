package com.ch4njun.cspm.demo.service;

import com.ch4njun.cspm.demo.constant.Path;
import com.ch4njun.cspm.demo.dto.AssessmentResultDto;
import com.ch4njun.cspm.demo.dto.MessageDto;
import com.ch4njun.cspm.demo.exception.AssessmentResultNotFoundException;
import com.ch4njun.cspm.demo.exception.AssessmentScriptException;
import com.ch4njun.cspm.demo.exception.HistoryAlreadyExistsException;
import com.ch4njun.cspm.demo.exception.HistoryNotFoundException;
import com.ch4njun.cspm.demo.model.AssessmentResult;
import com.ch4njun.cspm.demo.model.History;
import com.ch4njun.cspm.demo.repository.AssessmentResultRepository;
import com.ch4njun.cspm.demo.repository.HistoryRepository;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.zeroturnaround.exec.ProcessExecutor;

import java.util.*;

@Service
public class AssessmentResultServiceImpl implements AssessmentResultService {
    @Autowired
    private AssessmentResultRepository assessmentResultRepository;
    @Autowired
    private HistoryRepository historyRepository;
    @Autowired
    private ModelMapper mapper;

    @Override
    public List<AssessmentResultDto.Response> findAssessmentResults(AssessmentResultDto.GetRequest requestDto) {
        boolean existHistoryId = requestDto.getHistoryId() != null;
        boolean existResourceId = requestDto.getResourceId() != null;
        boolean existResult = requestDto.getResult() != null;

        List<AssessmentResult> assessmentResults;
        if (!existHistoryId && !existResourceId) {
            if (!existResult)
                assessmentResults = assessmentResultRepository.findAll();
            else
                assessmentResults = assessmentResultRepository.findAssessmentResultsByResult(requestDto.getResult());
        }else {
            if (!existHistoryId) {
                if (!existResult)
                    assessmentResults = assessmentResultRepository.findAssessmentResultsByResourceId(requestDto.getResourceId());
                else
                    assessmentResults = assessmentResultRepository.findAssessmentResultsByResourceIdAndResult(requestDto.getResourceId(), requestDto.getResult());
            }else {
                History history = historyRepository.findHistoryByHistoryId(requestDto.getHistoryId());
                if (history == null) {
                    throw new HistoryNotFoundException(String.format("History ID[%s] not found", requestDto.getHistoryId()));
                }

                if (!existResourceId) {
                    if (!existResult)
                        assessmentResults = assessmentResultRepository.findAssessmentResultsByHistory(history);
                    else
                        assessmentResults = assessmentResultRepository.findAssessmentResultsByHistoryAndResult(history, requestDto.getResult());
                }else {
                    if (!existResult)
                        assessmentResults = assessmentResultRepository.findAssessmentResultsByHistoryAndResourceId(history, requestDto.getResourceId());
                    else
                        assessmentResults = assessmentResultRepository.findAssessmentResultsByHistoryAndResourceIdAndResult(history, requestDto.getResourceId(), requestDto.getResult());
                }
            }
        }
        List<AssessmentResultDto.Response> responseDto = new ArrayList<>();
        assessmentResults.forEach(v -> {
            responseDto.add(mapper.map(v, AssessmentResultDto.Response.class));
        });
        return responseDto;
    }

    @Override
    public AssessmentResultDto.Response findAssessmentResultById(int id) {
        Optional<AssessmentResult> assessmentResult = assessmentResultRepository.findById(id);
        if (assessmentResult.isEmpty()) {
            throw new AssessmentResultNotFoundException(String.format("ID[%s] not found", id));
        }
        return mapper.map(assessmentResult, AssessmentResultDto.Response.class);
    }

    @Override
    public MessageDto runAssessmentScript(AssessmentResultDto.Run runDto) {
        if (historyRepository.findHistoryByHistoryId(runDto.getHistoryId()) != null) {
            throw new HistoryAlreadyExistsException(String.format("History ID[%s] already exists", runDto.getHistoryId()));
        }

        try {
            String output = new ProcessExecutor().command(Path.PYTHON_PATH, Path.ASSESSMENT_SCRIPT_PATH, String.valueOf(runDto.getHistoryId()),
                    String.valueOf(runDto.getAccessKey()), String.valueOf(runDto.getSecretKey()), String.valueOf(runDto.getRegionName()),
                    Arrays.toString(runDto.getServices()))
                    .readOutput(true)
                    .execute()
                    .outputString("EUC-KR");
            System.out.println(output);

            History history = historyRepository.findHistoryByHistoryId(runDto.getHistoryId());
            history.setStatus("Complete");
            historyRepository.save(history);
            return new MessageDto("Complete", output);
        } catch (Exception e) {
            throw new AssessmentScriptException(String.format("Assessment Script Error: [%s]", e.getMessage()));
        }
    }

    @Override
    public AssessmentResultDto.Response saveInterview(int id, AssessmentResultDto.PutRequest requestDto) {
        Optional<AssessmentResult> assessmentResult_original = assessmentResultRepository.findById(id);
        if (assessmentResult_original.isEmpty()) {
            throw new AssessmentResultNotFoundException(String.format("ID[%s] not found", id));
        }

        AssessmentResult assessmentResult_after = assessmentResult_original.get();
        assessmentResult_after.setResult(requestDto.getResult());
        assessmentResult_after.setInterview(requestDto.isInterview());
        assessmentResult_after.setInterviewContent(requestDto.getInterviewContent());

        AssessmentResult assessmentResult = assessmentResultRepository.save(assessmentResult_after);
        return mapper.map(assessmentResult, AssessmentResultDto.Response.class);
    }
}
