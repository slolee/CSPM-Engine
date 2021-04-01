package com.ch4njun.cspm.demo.resource;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Repository
public interface ResourceRepository extends JpaRepository<Resource, Integer> {
    List<Resource> findResourcesByAccessKey(String accessKey);
    List<Resource> findResourcesByAccessKeyAndService(String accessKey, String service);
    void deleteResourcesByAccessKey(String accessKey);
}
