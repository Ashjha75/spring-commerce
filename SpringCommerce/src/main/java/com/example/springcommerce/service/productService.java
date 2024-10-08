package com.example.springcommerce.service;

import com.example.springcommerce.DTO.Request.productRequest;
import com.example.springcommerce.DTO.Response.productResponse;
import org.springframework.web.multipart.MultipartFile;

public interface productService {

    productRequest addProduct(productRequest productEntity, Long categoryId);

    productResponse getAllProducts();

    productResponse getProductByCategory(Long categoryId);

    productResponse getProductByKeyWord(String keyWord);

    productRequest updateProduct(productRequest productEntity, Long productId);

    productRequest deleteProduct(Long productId);

    productRequest updateProductImage(Long productId, MultipartFile image);
}
