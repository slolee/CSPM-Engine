package com.ch4njun.cspm.demo.service;

import com.ch4njun.cspm.demo.dto.HistoryDto;
import com.ch4njun.cspm.demo.exception.HistoryNotFoundException;
import com.ch4njun.cspm.demo.model.History;
import com.ch4njun.cspm.demo.repository.AssessmentResultRepository;
import com.ch4njun.cspm.demo.repository.HistoryRepository;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class HistoryServiceImpl implements HistoryService {
    @Autowired
    private HistoryRepository historyRepository;

    @Autowired
    private AssessmentResultRepository assessmentResultRepository;

    @Autowired
    private ModelMapper mapper;

    @Override
    public HistoryDto.Response findHistoryByHistoryId(String historyId) {
        History history = historyRepository.findHistoryByHistoryId(historyId);
        if (history == null) {
            throw new HistoryNotFoundException(String.format("History ID[%s] Not Found", historyId));
        }
        return mapper.map(history, HistoryDto.Response.class);
    }

    @Override
    public void deleteHistoriesByHistoryId(String[] historiesId) {
        for (String historyId : historiesId) {
            History deleteHistory = historyRepository.findHistoryByHistoryId(historyId);
            if (deleteHistory == null)
                continue;

            historyRepository.deleteHistoryByHistoryId(historyId);
            assessmentResultRepository.deleteByHistory(deleteHistory);
        }
    }
}
