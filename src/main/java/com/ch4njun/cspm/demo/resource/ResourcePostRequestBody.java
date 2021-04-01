package com.ch4njun.cspm.demo.resource;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ResourcePostRequestBody {
    private String accessKey;
    private String secretKey;
    private String regionName;
}
