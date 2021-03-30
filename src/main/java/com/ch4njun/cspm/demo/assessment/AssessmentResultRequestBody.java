package com.ch4njun.cspm.demo.assessment;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AssessmentResultRequestBody {
    private int history_id;
    private String access_key;
    private String secret_key;
    private String region_name;
    private String[] services;
}
