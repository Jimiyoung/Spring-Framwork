package com.spring.javagreenS.service;

import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.multipart.MultipartFile;

import com.spring.javagreenS.dao.StudyDAO;
import com.spring.javagreenS.vo.OperatorVO;

@Service
public class StudyServiceImpl implements StudyService {
	
	@Autowired
	StudyDAO studyDAO;

	@Override
	public OperatorVO getOperator(String oid) {
		return studyDAO.getOperator(oid);
	}

	@Override
	public void setOperatorInputOk(OperatorVO vo) {
		// 1~50까지 난수를 구해서 해당 난수의 hashKey값을 operatorHashTable2에서 가져와 연산
		int keyIdx = (int) (Math.random()*50)+1;
		
		// 비밀번호 암호화 시켜주는 메소드를 호출해서 처리.
		String strPwd = setPasswordEncoding(vo.getPwd(),keyIdx);
		
		vo.setPwd(strPwd);
		vo.setKeyIdx(keyIdx);
		
		studyDAO.setOperatorInputOk(vo); // 잘 정리된 vo를 db에 저장
	}

	// 암호화 시켜주는 메소드
	private String setPasswordEncoding(String pwd, int keyIdx) {
		String hashKey = studyDAO.getOperatorHashKey(keyIdx);
		
	//입력된 비밀번호를 아스키코드로 변환하여 누적처리
			long intPwd;
			String strPwd = ""; 
			pwd = pwd.toUpperCase();
			
			for(int i=0; i<pwd.length(); i++) {
				intPwd = (long) pwd.charAt(i);  // A=65
				strPwd += intPwd; // 위에서 바뀐거 누적
			}
			// 문자로 결합된 숫자를 연산하기 위해 다시 숫자로 변환.
			intPwd = Long.parseLong(strPwd);
			
			//암호화를 위한 키 : hashKey 
			long key =Integer.parseInt(hashKey,16);
			long encPwd;
			
			//암호화를 위한 EOR 연산
			encPwd = intPwd ^ key;  //암호화 : DB에 저장
			strPwd = String.valueOf(encPwd); //암호화된 자료를 문자로 변환
		
		return strPwd;
	}

	@Override
	public ArrayList<OperatorVO> getOperatorList() {
		return studyDAO.getOperatorList();
	}

	@Override
	public void setOperatorDelete(String oid) {
		studyDAO.setOperatorDelete(oid);
	}

	@Override
	public String setOperatorSearch(OperatorVO vo) {
		String oid = vo.getOid();
		String pwd = vo.getPwd();
		
		vo = studyDAO.getOperator(oid);
		
		if(vo == null) return "0"; // 등록된 아이디 없음
		
		//검색된 아이디가 존재한다면 입력받은 pwd를 암호화해서 db의 pwd와 같은지 비교.
		String strPwd = setPasswordEncoding(pwd, vo.getKeyIdx());  // pwd를 암호화
		
		if(strPwd.equals(vo.getPwd())) return "1";
		
		return "0";
	}

	@Override
	public String[] getCityStringArr(String dodo) {
		String[] strArr = new String[100];
		
		if(dodo.equals("서울")) {
			strArr[0] = "강남구";
			strArr[1] = "강북구";
			strArr[2] = "서초구";
			strArr[3] = "도봉구";
			strArr[4] = "강동구";
			strArr[5] = "강서구";
			strArr[6] = "관악구";
			strArr[7] = "은평구";
			strArr[8] = "노원구";
			strArr[9] = "종로구";
		}
		else if(dodo.equals("경기")) {
			strArr[0] = "수원시";
			strArr[1] = "고양시";
			strArr[2] = "부천시";
			strArr[3] = "성남시";
			strArr[4] = "여주시";
			strArr[5] = "용인시";
			strArr[6] = "평택시";
			strArr[7] = "광명시";
			strArr[8] = "김포시";
			strArr[9] = "의정부시";
		}
		else if(dodo.equals("충북")) {
			strArr[0] = "청주시";
			strArr[1] = "충주시";
			strArr[2] = "제천시";
			strArr[3] = "진천군";
			strArr[4] = "괴산군";
			strArr[5] = "음성군";
			strArr[6] = "단양시";
			strArr[7] = "영동군";
			strArr[8] = "보은군";
			strArr[9] = "증평군";
		}
		else if(dodo.equals("충남")) {
			strArr[0] = "천안시";
			strArr[1] = "아산시";
			strArr[2] = "논산시";
			strArr[3] = "당진시";
			strArr[4] = "태안군";
			strArr[5] = "공주시";
			strArr[6] = "서천군";
			strArr[7] = "보령시";
			strArr[8] = "금산군";
			strArr[9] = "청양군";
		}
		return strArr;
	}

	@Override
	public ArrayList<String> getCityStringListStr(String dodo) {
		ArrayList<String> vos = new ArrayList<String>();
		
		if(dodo.equals("서울")) {
			vos.add("강남구");
			vos.add("강북구");
			vos.add("서초구");
			vos.add("도봉구");
			vos.add("강동구");
			vos.add("강서구");
			vos.add("관악구");
			vos.add("은평구");
			vos.add("노원구");
			vos.add("종로구");
		}
		else if(dodo.equals("경기")) {
			vos.add("수원시");
			vos.add("고양시");
			vos.add("부천시");
			vos.add("성남시");
			vos.add("여주시");
			vos.add("용인시");
			vos.add("평택시");
			vos.add("광명시");
			vos.add("김포시");
			vos.add("의정부시");
		}
		else if(dodo.equals("충북")) {
			vos.add("청주시");
			vos.add("충주시");
			vos.add("제천시");
			vos.add("진천군");
			vos.add("괴산군");
			vos.add("음성군");
			vos.add("단양시");
			vos.add("영동군");
			vos.add("보은군");
			vos.add("증평군");
		}
		else if(dodo.equals("충남")) {
			vos.add("천안시");
			vos.add("아산시");
			vos.add("논산시");
			vos.add("당진시");
			vos.add("태안군");
			vos.add("공주시");
			vos.add("서천군");
			vos.add("보령시");
			vos.add("금산군");
			vos.add("청양군");
		}                 
		return vos;
	}

	@Override
	public ArrayList<OperatorVO> getOperatorVos(String oid) {
		return studyDAO.getOperatorVos(oid);
	}

	@Override
	public int fileUpload(MultipartFile fName) {
		int res = 0;
		try {
			UUID uid = UUID.randomUUID();
			String oFileName = fName.getOriginalFilename();
			String saveFileName = uid + "_" + oFileName ;
			
			writeFile(fName, saveFileName);
			res=1;
		} catch (IOException e) {
			e.printStackTrace();
		}
		return res;
	}

	private void writeFile(MultipartFile fName, String saveFileName) throws IOException{
		byte[] data = fName.getBytes();  //넘어온 객체를 바이트단위로 바꿈
		
		HttpServletRequest request = ((ServletRequestAttributes)RequestContextHolder.currentRequestAttributes()).getRequest();
		String uploadPath = request.getSession().getServletContext().getRealPath("/resources/images/test/");
		
		FileOutputStream fos = new FileOutputStream(uploadPath+saveFileName);
		fos.write(data);
		fos.close();
	}
}
