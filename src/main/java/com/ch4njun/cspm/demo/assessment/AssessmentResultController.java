package com.ch4njun.cspm.demo.assessment;

import com.ch4njun.cspm.demo.history.History;
import com.ch4njun.cspm.demo.history.HistoryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.zeroturnaround.exec.ProcessExecutor;

import java.io.File;
import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/assessment-results")
public class AssessmentResultController {
    @Autowired
    private AssessmentResultRepository assessmentResultRepository;
    @Autowired
    private HistoryRepository historyRepository;

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
        System.out.println(body.getRegion_name());
        System.out.println(Arrays.toString(body.getServices()));

        History history = new History(body.getHistory_id(), "running");
        historyRepository.save(history);

        String pythonPath = "src\\main\\java\\com\\ch4njun\\cspm\\demo\\engine\\check_main.py";
        String python = "D:\\Install\\Python3";
        try {
            String output = new ProcessExecutor().command(python + "\\python.exe", pythonPath, String.valueOf(body.getHistory_id()),
                    String.valueOf(body.getAccess_key()), String.valueOf(body.getSecret_key()), String.valueOf(body.getRegion_name()),
                    Arrays.toString(body.getServices()))
                    .readOutput(true)
                    .execute()
                    .outputString("EUC-KR");
            System.out.println(output);
        }catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
}
