package com.thiago.valhallaproject.service;

import com.thiago.valhallaproject.domain.GodName;
import com.thiago.valhallaproject.repository.GodNameRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class GodNameService {
    private final GodNameRepository godNameRepository;

    public Iterable<GodName> findAll(Pageable pageable) {
        return godNameRepository.findAll(pageable);
    }

    public GodName save(GodName godName){
        return godNameRepository.save(godName);
    }
}
