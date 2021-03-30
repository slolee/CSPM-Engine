package com.ch4njun.cspm.demo.assessment;

import com.ch4njun.cspm.demo.history.History;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
public class AssessmentResult {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    @ManyToOne
    private History history;

    private String service;

    private int chkIndex;

    private String resourceId;

    private String result;

    @Lob
    private String rawData;

    private boolean interview;

    @Lob
    private String interview_content;
}
