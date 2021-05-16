package com.ch4njun.cspm.demo.assessment;

import com.ch4njun.cspm.demo.history.History;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AssessmentResultRepository extends JpaRepository<AssessmentResult, Integer> {
    List<AssessmentResult> findAssessmentResultsByResult(String result);
    List<AssessmentResult> findAssessmentResultsByHistoryAndResult(History history, String result);
    List<AssessmentResult> findAssessmentResultsByHistoryAndResourceIdAndResult(History history, String ResourceName, String result);
    List<AssessmentResult> findAssessmentResultsByResourceIdAndResult(String ResourceId, String result);
    List<AssessmentResult> findAssessmentResultsByHistory(History history);
    List<AssessmentResult> findAssessmentResultsByHistoryAndResourceId(History history, String ResourceId);
    List<AssessmentResult> findAssessmentResultsByResourceId(String ResourceId);
    void deleteByHistory(History history);
}
