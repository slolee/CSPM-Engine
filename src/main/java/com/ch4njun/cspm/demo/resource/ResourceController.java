package com.ch4njun.cspm.demo.resource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import org.zeroturnaround.exec.ProcessExecutor;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/resources")
public class ResourceController {
    @Autowired
    private ResourceRepository resourceRepository;

    @GetMapping("")
    public List<Resource> retrieveResources(@RequestParam String accessKey,
                                            @RequestParam(required = false) String service) {

        List<Resource> resources = null;
        if (service == null)
            resources = resourceRepository.findResourcesByAccessKey(accessKey);
        else
            resources = resourceRepository.findResourcesByAccessKeyAndService(accessKey, service);

        return resources;
    }

    @GetMapping("/{id}")
    public Resource retrieveResource(@PathVariable int id) {
        Optional<Resource> resource = resourceRepository.findById(id);
        if (resource.isEmpty()) {
            return null;
        }

        return resource.get();
    }

    @PostMapping("")
    @Transactional
    public void run(@RequestBody ResourcePostRequestBody body) {
        resourceRepository.deleteResourcesByAccessKey(body.getAccessKey());

        try {
            String pythonPath = "src\\main\\resources\\engine\\resource\\load_resource_main.py";
            String python = "D:\\Install\\Python3";

            String output = new ProcessExecutor().command(python + "\\python.exe", pythonPath, String.valueOf(body.getAccessKey()),
                    String.valueOf(body.getSecretKey()), String.valueOf(body.getRegionName()))
                    .readOutput(true)
                    .execute()
                    .outputString("EUC-KR");
            System.out.println(output);
        }catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    @DeleteMapping("")
    @Transactional
    public void deleteResources(@RequestBody ResourceDeleteRequestBody body) {
        for (String accessKey : body.getAccessKeys()) {
            if (resourceRepository.findResourcesByAccessKey(accessKey) == null)
                continue;
            resourceRepository.deleteResourcesByAccessKey(accessKey);
        }
    }
}
