package com.example.springcommerce.DTO.Response;


import com.example.springcommerce.DTO.Request.productRequest;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class productResponse {
    private List<productRequest> products;

    private Integer pageNumber;
    private Integer pageSize;
    private Long totalElments;
    private Integer totalPages;
    private boolean isLastPage;
}
