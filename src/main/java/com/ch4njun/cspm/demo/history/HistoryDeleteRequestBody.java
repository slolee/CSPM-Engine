package com.ch4njun.cspm.demo.history;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class HistoryDeleteRequestBody {
    private String[] historiesId;
}
