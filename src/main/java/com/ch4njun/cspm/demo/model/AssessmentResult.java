package com.ch4njun.cspm.demo.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.ColumnDefault;

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

    private String resourceName;

    private String resourceId;

    private String result;

    @Lob
    private String rawData;

    @ColumnDefault("false")
    private boolean interview;

    @Lob
    private String interviewContent;
}
