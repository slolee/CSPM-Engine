package com.ch4njun.cspm.demo.dto;

import lombok.Data;

public class HistoryDto {
    @Data
    public static class DeleteRequest {
        private String[] historiesId;
    }

    @Data
    public static class Response {
        private String historyId;
        private String status;
    }
}
