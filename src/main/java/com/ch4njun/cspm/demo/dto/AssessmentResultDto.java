package com.ch4njun.cspm.demo.dto;

import com.ch4njun.cspm.demo.model.History;
import lombok.AllArgsConstructor;
import lombok.Data;

public class AssessmentResultDto {
    @Data
    public static class Run {
        private String historyId;
        private String accessKey;
        private String secretKey;
        private String regionName;
        private String[] services;
    }

    @Data
    @AllArgsConstructor
    public static class GetRequest {
        private String historyId;
        private String resourceId;
        private String result;
    }

    @Data
    public static class PutRequest {
        private String result;
        private boolean interview;
        private String interviewContent;
    }

    @Data
    public static class Response {
        private int id;
        private String service;
        private int chkIndex;
        private String resourceName;
        private String resourceId;
        private String result;
        private String rawData;
        private boolean interview;
        private String interviewContent;
        private History history;
    }
}
