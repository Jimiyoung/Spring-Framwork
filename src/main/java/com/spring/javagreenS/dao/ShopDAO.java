package com.spring.javagreenS.dao;

import java.util.ArrayList;

import org.apache.ibatis.annotations.Param;

import com.spring.javagreenS.vo.ProductVO;

public interface ShopDAO {

	public ArrayList<String> getProduct1();

	public ArrayList<String> getProduct2(@Param("product1") String product1);

	public ArrayList<String> getProduct3(@Param("product1") String product1, @Param("product2") String product2);

	public void setProductInput(@Param("vo") ProductVO vo);

	public ArrayList<ProductVO> getProductList(@Param("product") String product);

}
