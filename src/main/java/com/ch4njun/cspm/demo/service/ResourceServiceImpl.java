package com.ch4njun.cspm.demo.service;

import com.ch4njun.cspm.demo.constant.Path;
import com.ch4njun.cspm.demo.dto.MessageDto;
import com.ch4njun.cspm.demo.dto.ResourceDto;
import com.ch4njun.cspm.demo.exception.ResourceNotFoundException;
import com.ch4njun.cspm.demo.exception.ResourceScriptException;
import com.ch4njun.cspm.demo.model.Resource;
import com.ch4njun.cspm.demo.repository.ResourceRepository;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.zeroturnaround.exec.ProcessExecutor;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class ResourceServiceImpl implements ResourceService {
    @Autowired
    private ResourceRepository resourceRepository;

    @Autowired
    private ModelMapper mapper;

    @Override
    public List<ResourceDto.Response> findResourcesByAccessKey(ResourceDto.GetRequest requestDto) {
        List<Resource> resources;
        if (requestDto.getService() == null)
            resources = resourceRepository.findResourcesByAccessKey(requestDto.getAccessKey());
        else
            resources = resourceRepository.findResourcesByAccessKeyAndService(requestDto.getAccessKey(), requestDto.getService());
        List<ResourceDto.Response> result = new ArrayList<>();
        resources.forEach(v -> {
            result.add(mapper.map(v, ResourceDto.Response.class));
        });
        return result;
    }

    @Override
    public ResourceDto.Response findResourceById(int id) {
        Optional<Resource> resource = resourceRepository.findById(id);
        if (resource.isEmpty()) {
            throw new ResourceNotFoundException(String.format("Resource ID[%s] Not Found", id));
        }
        return mapper.map(resource.get(), ResourceDto.Response.class);
    }

    @Override
    public MessageDto runResourceScript(ResourceDto.Run runDto) {
        resourceRepository.deleteResourcesByAccessKey(runDto.getAccessKey());

        try {
            String output = new ProcessExecutor().command(Path.PYTHON_PATH, Path.RESOURCE_SCRIPT_PATH, String.valueOf(runDto.getAccessKey()),
                    String.valueOf(runDto.getSecretKey()), String.valueOf(runDto.getRegionName()))
                    .readOutput(true)
                    .execute()
                    .outputString("EUC-KR");
            System.out.println(output);
            return new MessageDto("Complete", output);
        } catch (Exception e) {
            throw new ResourceScriptException(String.format("Resource Script Error: [%s]", e.getMessage()));
        }
    }

    @Override
    public void deleteResourcesByAccessKey(ResourceDto.DeleteRequest requestDto) {
        for(String accessKey: requestDto.getAccessKeys()) {
            if (resourceRepository.findResourcesByAccessKey(accessKey) == null)
                continue;
            resourceRepository.deleteResourcesByAccessKey(accessKey);
        }
    }
}
