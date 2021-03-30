package com.ch4njun.cspm.demo.history;

import com.ch4njun.cspm.demo.assessment.AssessmentResult;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
public class History {
    public History(String historyId, String status) {
        this.historyId = historyId;
        this.status = status;
    }

    @Id
    @GeneratedValue
    private int id;

    @Column(unique = true)
    private String historyId;

    private String status;

    @OneToMany(mappedBy = "history", cascade = {CascadeType.ALL})
    @JsonIgnore
    private List<AssessmentResult> assessmentResults;
}
