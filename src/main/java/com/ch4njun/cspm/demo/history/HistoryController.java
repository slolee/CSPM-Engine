package com.ch4njun.cspm.demo.history;

import com.ch4njun.cspm.demo.assessment.AssessmentResultRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/histories")
public class HistoryController {
    @Autowired
    private HistoryRepository historyRepository;
    @Autowired
    private AssessmentResultRepository assessmentResultRepository;

    @GetMapping("/{historyId}")
    @CrossOrigin(origins = "*", allowedHeaders = "*")
    public History retrieveHistory(@PathVariable String historyId) {
        History history = historyRepository.findHistoryByHistoryId(historyId);
        if (history == null) {
            throw new HistoryNotFoundException(String.format("History ID[%s] Not Found", historyId));
        }
        return history;
    }

    @Transactional
    @DeleteMapping("")
    @CrossOrigin(origins = "*", allowedHeaders = "*")
    public void deleteHistories(@RequestBody HistoryDeleteRequestBody body) {
        for (String historyId : body.getHistoriesId()) {
            History deleteHistory = historyRepository.findHistoryByHistoryId(historyId);
            if (deleteHistory == null)
                continue;
            historyRepository.deleteHistoryByHistoryId(historyId);
            assessmentResultRepository.deleteByHistory(deleteHistory);
        }
    }

    @Transactional
    @DeleteMapping("/all")
    @CrossOrigin(origins = "*", allowedHeaders = "*")
    public void deleteHistoriesAll() {
        historyRepository.deleteAll();
        assessmentResultRepository.deleteAll();
    }
}
