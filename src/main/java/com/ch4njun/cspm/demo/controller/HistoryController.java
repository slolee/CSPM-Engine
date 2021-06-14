package com.ch4njun.cspm.demo.controller;

import com.ch4njun.cspm.demo.dto.HistoryDto;
import com.ch4njun.cspm.demo.service.HistoryService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/histories")
public class HistoryController {
    @Autowired
    private HistoryService historyService;

    @GetMapping("/{historyId}")
    public ResponseEntity<HistoryDto.Response> retrieveHistory(@PathVariable String historyId) {
        HistoryDto.Response responseDto = historyService.findHistoryByHistoryId(historyId);
        return new ResponseEntity<>(responseDto, HttpStatus.OK);
    }

    @Transactional
    @DeleteMapping("")
    public ResponseEntity<Void> deleteHistories(@RequestBody HistoryDto.DeleteRequest requestDto) {
        historyService.deleteHistoriesByHistoryId(requestDto.getHistoriesId());
        return new ResponseEntity<>(HttpStatus.OK);
    }
}
