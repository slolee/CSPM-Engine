package com.ch4njun.cspm.demo.repository;

import com.ch4njun.cspm.demo.model.Resource;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ResourceRepository extends JpaRepository<Resource, Integer> {
    List<Resource> findResourcesByAccessKey(String accessKey);
    List<Resource> findResourcesByAccessKeyAndService(String accessKey, String service);
    void deleteResourcesByAccessKey(String accessKey);
}
