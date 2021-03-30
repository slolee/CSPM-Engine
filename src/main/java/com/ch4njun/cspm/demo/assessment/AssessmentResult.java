package com.ch4njun.cspm.demo.assessment;

import com.ch4njun.cspm.demo.history.History;
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

    @ManyToOne(fetch = FetchType.LAZY)
    private History history;

    private String service;

    private int chk_index;

    private String resource_id;

    private String result;

    @Lob
    private String raw_data;

    private boolean interview;

    @Lob
    private String interview_content;
}
