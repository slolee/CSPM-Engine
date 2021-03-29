package com.ch4njun.cspm.demo.assessment;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.zeroturnaround.exec.ProcessExecutor;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/assessment-results")
public class AssessmentResultController {
    @Autowired
    private AssessmentResultRepository assessmentResultRepository;

    @GetMapping("")
    public List<AssessmentResult> retrieveAssessmentResults(@RequestParam int history_id, @RequestParam String check) {
        System.out.println("Params : " + history_id + ", " + check);
        return null;
        // return assessmentResultRepository.findAll();
    }

    @PostMapping("")
    public void run(@RequestBody AssessmentResultRequestBody body) {
        System.out.println(body.getHistory_id());
        System.out.println(body.getAccess_key());
        System.out.println(body.getSecret_key());
        System.out.println(Arrays.toString(body.getServices()));

//        Runtime rt = Runtime.getRuntime();
//        String file = "C:\\Windows\\System32\\calc.exe";
//        Process pro;
//        try {
//            pro = rt.exec(file);
//            pro.waitFor();
//        }catch (Exception e) {
//            e.printStackTrace();
//        }

//        String pythonPath = "C:\\Users\\박찬준\\IdeaProjects\\cspm-engine-service\\src\\main\\java\\com\\ch4njun\\cspm\\demo\\engine\\test.py";
//        String python = "D:\\Install\\Python3";
//        try {
//            ProcessBuilder pb = new ProcessBuilder(python + "\\python.exe", pythonPath);
//            pb.start();
//        }catch (Exception e) {
//            System.out.println(e.getMessage());
//        }


        String pythonPath = "C:\\Users\\박찬준\\IdeaProjects\\cspm-engine-service\\src\\main\\java\\com\\ch4njun\\cspm\\demo\\engine\\test.py";
        String python = "D:\\Install\\Python3";
        try {
            new ProcessExecutor().command(python + "\\python.exe", pythonPath).execute();
        }catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
}
