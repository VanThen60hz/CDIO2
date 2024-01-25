package com.example.be.dto.request;

import lombok.Value;

import java.io.Serializable;

/**
 * DTO for {@link com.example.be.entity.Faculty}
 */
@Value
public class FacultyDto implements Serializable {
    Integer facultyId;
    String name;
}