package com.thiago.valhallaproject.controller;

import com.thiago.valhallaproject.domain.GodName;
import com.thiago.valhallaproject.service.GodNameService;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("names")
public class GodNameController {

    private GodNameService godNameService;

    @GetMapping
    public ResponseEntity<Iterable<GodName>> findAll(Pageable pageable) {
        return new ResponseEntity<>(godNameService.findAll(pageable), HttpStatus.OK);
    }
}
