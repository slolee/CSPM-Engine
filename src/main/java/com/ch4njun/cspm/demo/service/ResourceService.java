package com.ch4njun.cspm.demo.service;

import com.ch4njun.cspm.demo.dto.MessageDto;
import com.ch4njun.cspm.demo.dto.ResourceDto;

import java.util.List;

public interface ResourceService {
    List<ResourceDto.Response> findResourcesByAccessKey(ResourceDto.GetRequest requestDto);
    ResourceDto.Response findResourceById(int id);
    MessageDto runResourceScript(ResourceDto.Run runDto);
    void deleteResourcesByAccessKey(ResourceDto.DeleteRequest requestDto);
}
