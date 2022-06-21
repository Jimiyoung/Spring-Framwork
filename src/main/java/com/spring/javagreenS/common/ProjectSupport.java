package com.spring.javagreenS.common;

import java.io.FileOutputStream;
import java.io.IOException;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;

import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.multipart.MultipartFile;

public class ProjectSupport {
	
	public int fileUpload(MultipartFile fName) {
		int res = 0;
		try {
			UUID uid = UUID.randomUUID();
			String oFileName = fName.getOriginalFilename();
			String saveFileName = uid + "_" + oFileName ;
			
			writeFile(fName, saveFileName,"");
			res=1;
		} catch (IOException e) {
			e.printStackTrace();
		}
		return res;
	}

	public void writeFile(MultipartFile fName, String saveFileName, String flag) throws IOException{
		byte[] data = fName.getBytes();  //넘어온 객체를 바이트단위로 바꿈
		
		HttpServletRequest request = ((ServletRequestAttributes)RequestContextHolder.currentRequestAttributes()).getRequest();
		String uploadPath="";
	
		uploadPath = request.getSession().getServletContext().getRealPath("/resources/"+flag+"/");
		
		
		FileOutputStream fos = new FileOutputStream(uploadPath+saveFileName);
		fos.write(data);
		fos.close();
	}
}
