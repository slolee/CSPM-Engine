package com.ch4njun.cspm.demo.controller;

import com.ch4njun.cspm.demo.dto.MessageDto;
import com.ch4njun.cspm.demo.dto.ResourceDto;
import com.ch4njun.cspm.demo.service.ResourceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/resources")
public class ResourceController {
    @Autowired
    private ResourceService resourceService;

    @GetMapping("")
    public ResponseEntity<List<ResourceDto.Response>> retrieveResources(@RequestParam String accessKey,
                                                           @RequestParam(required = false) String service) {
        ResourceDto.GetRequest requestDto = new ResourceDto.GetRequest(accessKey, service);
        List<ResourceDto.Response> responseDto = resourceService.findResourcesByAccessKey(requestDto);
        return new ResponseEntity<>(responseDto, HttpStatus.OK);
    }

    @GetMapping("/{id}")
    public ResponseEntity<ResourceDto.Response> retrieveResource(@PathVariable int id) {
        ResourceDto.Response responseDto = resourceService.findResourceById(id);
        return new ResponseEntity<>(responseDto, HttpStatus.OK);
    }

    @PostMapping("")
    @Transactional
    public ResponseEntity<MessageDto> run(@RequestBody ResourceDto.Run runDto) {
        MessageDto messageDto = resourceService.runResourceScript(runDto);
        return new ResponseEntity<>(messageDto, HttpStatus.OK);

    }

    @DeleteMapping("")
    @Transactional
    public ResponseEntity<Void> deleteResources(@RequestBody ResourceDto.DeleteRequest requestDto) {
        resourceService.deleteResourcesByAccessKey(requestDto);
        return new ResponseEntity<>(HttpStatus.OK);
    }
}
