package com.ch4njun.cspm.demo.repository;

import com.ch4njun.cspm.demo.model.History;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface HistoryRepository extends JpaRepository<History, Integer> {
    History findHistoryByHistoryId(String historyId);
    void deleteHistoryByHistoryId(String historyId);
}
