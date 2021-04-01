package com.ch4njun.cspm.demo.resource;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ResourceDeleteRequestBody {
    private String[] accessKeys;
}
