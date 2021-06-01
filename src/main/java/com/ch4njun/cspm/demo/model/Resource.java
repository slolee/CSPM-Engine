package com.ch4njun.cspm.demo.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
public class Resource {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    private String accessKey;

    private String service;

    private String resourceType;

    private String resourceName;

    private String resourceId;

    @Lob
    private String tag;
}
