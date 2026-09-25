package com.cbcbourse.usermanagement.common.dto;

import org.springframework.data.domain.Page;

import java.util.List;

/** Représentation JSON stable d'une page de résultats. */
public record PageResponse<T>(
        List<T> content,
        int page,
        int size,
        long totalElements,
        int totalPages
) {
    public static <T> PageResponse<T> from(Page<T> page) {
        return new PageResponse<>(page.getContent(), page.getNumber(), page.getSize(),
                page.getTotalElements(), page.getTotalPages());
    }
}
