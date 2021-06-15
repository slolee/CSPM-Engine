package com.ch4njun.cspm.demo.constant;

public class Path {
    public static String PYTHON_PATH;
    public static String ASSESSMENT_SCRIPT_PATH;
    public static String RESOURCE_SCRIPT_PATH;

    static {
        String os = System.getProperty("os.name").toLowerCase();
        System.out.println(os);

        if (os.contains("win")) {
            PYTHON_PATH = "python";
            ASSESSMENT_SCRIPT_PATH = "src\\main\\resources\\engine\\assessment\\assessment_main.py";
            RESOURCE_SCRIPT_PATH = "src\\main\\resources\\engine\\resource\\load_resource_main.py";
        }else if (os.contains("linux")) {
            PYTHON_PATH = "python3";
            // 수정 필요
            ASSESSMENT_SCRIPT_PATH = "/home/ec2-user/CSPM-Engine-Linux/src/main/resources/engine/assessment/assessment_main.py";
            RESOURCE_SCRIPT_PATH = "/home/ec2-user/CSPM-Engine-Linux/src/main/resources/engine/resource/load_resource_main.py";
        }
    }
}
