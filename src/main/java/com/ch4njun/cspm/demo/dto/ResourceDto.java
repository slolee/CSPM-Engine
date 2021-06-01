package com.ch4njun.cspm.demo.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

public class ResourceDto {
    @Data
    public static class Run {
        private String accessKey;
        private String secretKey;
        private String regionName;
    }

    @Data
    @AllArgsConstructor
    public static class GetRequest {
        private String accessKey;
        private String service;
    }

    @Data
    public static class DeleteRequest {
        private String[] accessKeys;
    }

    @Data
    public static class Response {
        private int id;
        private String accessKey;
        private String service;
        private String resourceType;
        private String resourceName;
        private String resourceId;
        private String tag;
    }
}
