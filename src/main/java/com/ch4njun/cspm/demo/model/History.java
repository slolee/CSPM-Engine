package com.ch4njun.cspm.demo.model;

import com.ch4njun.cspm.demo.model.AssessmentResult;
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
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @JsonIgnore
    private int id;

    @Column(unique = true)
    private String historyId;

    private String status;

    @OneToMany(mappedBy = "history", cascade = CascadeType.ALL)
    @JsonIgnore
    private List<AssessmentResult> assessmentResults;
}
