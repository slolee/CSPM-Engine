package com.ch4njun.cspm.demo.history;

import com.ch4njun.cspm.demo.assessment.AssessmentResult;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
public class History {
    @Id
    private int history_id;

    private String status;

    @OneToMany(mappedBy = "history")
    @JsonIgnore
    private List<AssessmentResult> assessment_results;
}
