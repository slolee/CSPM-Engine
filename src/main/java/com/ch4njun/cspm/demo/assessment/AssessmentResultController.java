package com.ch4njun.cspm.demo.assessment;

import com.ch4njun.cspm.demo.history.History;
import com.ch4njun.cspm.demo.history.HistoryAlreadyExistsException;
import com.ch4njun.cspm.demo.history.HistoryNotFoundException;
import com.ch4njun.cspm.demo.history.HistoryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import org.zeroturnaround.exec.ProcessExecutor;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/assessment-results")
public class AssessmentResultController {
    @Autowired
    private AssessmentResultRepository assessmentResultRepository;
    @Autowired
    private HistoryRepository historyRepository;

    @GetMapping("")
    public List<AssessmentResult> retrieveAssessmentResults(@RequestParam(required = false) String historyId,
                                                            @RequestParam(required = false) String resourceId,
                                                            @RequestParam(required = false) String result) {
        List<AssessmentResult> assessmentResults = null;
        if (historyId == null && resourceId == null) {
            if (result == null)
                assessmentResults = assessmentResultRepository.findAll();
            else
                assessmentResults = assessmentResultRepository.findAssessmentResultsByResult(result);
        }else {
            if (historyId == null) {
                if (result == null)
                    assessmentResults = assessmentResultRepository.findAssessmentResultsByResourceId(resourceId);
                else
                    assessmentResults = assessmentResultRepository.findAssessmentResultsByResourceIdAndResult(resourceId, result);
            }else {
                History history = historyRepository.findHistoryByHistoryId(historyId);
                if (history == null) {
                    throw new HistoryNotFoundException(String.format("History ID[%s] not found", historyId));
                }

                if (resourceId == null) {
                    if (result == null)
                        assessmentResults = assessmentResultRepository.findAssessmentResultsByHistory(history);
                    else
                        assessmentResults = assessmentResultRepository.findAssessmentResultsByHistoryAndResult(history, result);
                }else {
                    if (result == null)
                        assessmentResults = assessmentResultRepository.findAssessmentResultsByHistoryAndResourceId(history, resourceId);
                    else
                        assessmentResults = assessmentResultRepository.findAssessmentResultsByHistoryAndResourceIdAndResult(history, resourceId, result);
                }
            }
        }
        return assessmentResults;
    }

    @GetMapping("/{id}")
    public AssessmentResult retrieveAssessmentResult(@PathVariable int id) {
        Optional<AssessmentResult> assessmentResult = assessmentResultRepository.findById(id);
        if (assessmentResult.isEmpty()) {
            throw new AssessmentResultNotFoundException(String.format("ID[%s] not found", id));
        }

        return assessmentResult.get();
    }

    @PostMapping("")
    @CrossOrigin(origins = "*", allowedHeaders = "*")
    public Message run(@RequestBody AssessmentResultPostRequestBody body) {
        if (historyRepository.findHistoryByHistoryId(body.getHistoryId()) != null) {
            throw new HistoryAlreadyExistsException(String.format("History ID[%s] already exists", body.getHistoryId()));
        }

        try {
            String pythonPath = "src\\main\\resources\\engine\\assessment\\assessment_main.py";
            String python = "D:\\Install\\Python3";
            String output = new ProcessExecutor().command(python + "\\python.exe", pythonPath, String.valueOf(body.getHistoryId()),
                    String.valueOf(body.getAccessKey()), String.valueOf(body.getSecretKey()), String.valueOf(body.getRegionName()),
                    Arrays.toString(body.getServices()))
                    .readOutput(true)
                    .execute()
                    .outputString("EUC-KR");
            System.out.println(output);

            History history = historyRepository.findHistoryByHistoryId(body.getHistoryId());
            history.setStatus("Complete");
            historyRepository.save(history);
            return new Message("Complete", output);
        }catch (Exception e) {
            System.out.println(e.getMessage());
            return null;
        }
    }

    @PutMapping("/{id}")
    @CrossOrigin(origins = "*", allowedHeaders = "*")
    public AssessmentResult interview(@PathVariable int id, @RequestBody AssessmentResult assessmentResult) {
        Optional<AssessmentResult> assessmentResult_original = assessmentResultRepository.findById(id);
        if (assessmentResult_original.isEmpty()) {
            return null;
        }

        AssessmentResult assessmentResult_after = assessmentResult_original.get();
        assessmentResult_after.setResult(assessmentResult.getResult());
        assessmentResult_after.setInterview(assessmentResult.isInterview());
        assessmentResult_after.setInterviewContent(assessmentResult.getInterviewContent());

        return assessmentResultRepository.save(assessmentResult_after);
    }
}
