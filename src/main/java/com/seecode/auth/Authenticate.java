package com.seecode.auth;

/**
 * Created by MyKings on 19/07/2019.
 */
public class Authenticate {

    public void LoginPasswordLeak(){
        // password leak
        String password = "1qaz@WSX";
    }


    public  void LoginFalsePositive(){

		// type 1
        String PARAM_NAME_PASSWORD = "pwd_txt";
        String PARAM_NAME_JMX_PASSWORD = "pwd_txt";
        String USER_PWD_ERROR = "pwd_txt";
        String DATE_FORMAT_PWD = "pwd_txt";
		// type 2
        String HOST_MAIL_PASSWORD= "";
        String despassword= "";
        String PASSWORD = "";
        String mqPassword = "";
		// type 3
        logger.info("Login password is invalid")
    }
}
