package com.example.be.dto.request;

import lombok.Value;

import java.io.Serializable;

/**
 * DTO for {@link com.example.be.entity.Degree}
 */
@Value
public class DegreeDto implements Serializable {
    Integer degreeId;
    String name;
}