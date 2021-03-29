package com.ch4njun.cspm.demo.assessment;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
public class AssessmentResult {
    @Id
    @GeneratedValue
    private int id;

    private int history_id;

    private String service;

    private int index;

    private String result;

    private String raw_data;

    private boolean interview;

    private String interview_content;
}
