package com.ch4njun.cspm.demo.history;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HistoryController {
    @Autowired
    private HistoryRepository historyRepository;
}
