package com.ch4njun.cspm.demo.assessment;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AssessmentResultPostRequestBody {
    private String historyId;
    private String accessKey;
    private String secretKey;
    private String regionName;
    private String[] services;
}
