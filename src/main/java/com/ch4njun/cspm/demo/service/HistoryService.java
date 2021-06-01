package com.ch4njun.cspm.demo.service;

import com.ch4njun.cspm.demo.dto.HistoryDto;

public interface HistoryService {
    HistoryDto.Response findHistoryByHistoryId(String historyId);
    void deleteHistoriesByHistoryId(String[] historiesId);
}
