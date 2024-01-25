package com.example.be.dto.request;

import lombok.Value;

import javax.validation.constraints.NotNull;
import java.io.Serializable;

/**
 * DTO for {@link com.example.be.entity.Teacher}
 */
@Value
public class SignUpRequest implements Serializable {
    String userName;
    String password;
    String name;
    String dateOfBirth;
    String address;
    String phone;
    String email;
    String avatar;
    Boolean gender;
    Boolean delete_flag;
    //    Integer facultyId;
//    Integer degreeId;
//    Integer accountId;
}