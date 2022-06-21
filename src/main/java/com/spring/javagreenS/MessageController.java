package com.spring.javagreenS;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class MessageController {

	@RequestMapping(value="/msg/{msgFlag}", method=RequestMethod.GET)
	public String msgGet(@PathVariable String msgFlag, Model model,
			@RequestParam(value="name", defaultValue = "", required=false) String name,
			@RequestParam(value="mid", defaultValue = "", required=false) String mid,
			@RequestParam(value="idx", defaultValue = "0", required=false) int idx) {
		
		if(msgFlag.equals("guestInputOk")) {
			model.addAttribute("msg", "방명록에 글이 등록 되었습니다.");
			model.addAttribute("url", "guest/guestList");
		}
		else if(msgFlag.equals("memberLogout")) {
			model.addAttribute("msg", name + "님 로그아웃 되었습니다.");
			model.addAttribute("url", "member/memberLogin");
		}
		else if(msgFlag.equals("operatorCheckNo")) {
			model.addAttribute("msg", "아이디가 중복되었습니다. 다시 입력하세요.");
			model.addAttribute("url", "study/password2/operatorMenu");
		}
		else if(msgFlag.equals("operatorInputOk")) {
			model.addAttribute("msg", "새로운 운영자로 등록되었습니다.");
			model.addAttribute("url", "study/password2/operatorMenu");
		}
		else if(msgFlag.equals("productInputOk")) {
			model.addAttribute("msg", "상품이 등록되었습니다.");
			model.addAttribute("url", "shop/input/productMenu");
		}
		else if(msgFlag.equals("mailSendOk")) {
			model.addAttribute("msg", "메일이 전송되었습니다.");
			model.addAttribute("url", "study/mail/mailForm");
		}
		else if(msgFlag.equals("MemIdCheckNo")) {
			model.addAttribute("msg", "이미 사용중인 아이디입니다.");
			model.addAttribute("url", "member/memJoin");
		}
		else if(msgFlag.equals("MemNickCheckNo")) {
			model.addAttribute("msg", "이미 사용중인 닉네임입니다.");
			model.addAttribute("url", "member/memJoin");
		}
		else if(msgFlag.equals("memInputOk")) {
			model.addAttribute("msg", "회원가입되었습니다.");
			model.addAttribute("url", "member/memLogin");
		}
		else if(msgFlag.equals("memInpuNo")) {
			model.addAttribute("msg", "회원가입 실패.");
			model.addAttribute("url", "member/memJoin");
		}
		else if(msgFlag.equals("fileUploadOk")) {
			model.addAttribute("msg", "파일이 업로드되었습니다.");
			model.addAttribute("url", "study/fileUpload/fileUpload");
		}
		else if(msgFlag.equals("fileUploadNo")) {
			model.addAttribute("msg", "파일 업로드에 실패하였습니다.");
			model.addAttribute("url", "study/fileUpload/fileUpload");
		}
		else if(msgFlag.equals("memLoginOk")) {
			model.addAttribute("msg", mid+"님 로그인 되었습니다.");
			model.addAttribute("url", "member/memMain");
		}
		else if(msgFlag.equals("memLoginNo")) {
			model.addAttribute("msg", "로그인 실패");
			model.addAttribute("url", "member/memLogin");
		}
		else if(msgFlag.equals("memLogout")) {
			model.addAttribute("msg", mid+"님 로그아웃 되셨습니다.");
			model.addAttribute("url", "member/memLogin");
		}
		
		return "include/message";
	}
	
}
