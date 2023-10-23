/*
* To change this license header, choose License Headers in Project Properties.
* To change this template file, choose Tools | Templates
* and open the template in the editor.
*/
package PassiveDigger;

import static PassiveDigger.PassiveAnalyzer.AnalyzeRequest;
import static PassiveDigger.PassiveAnalyzer.AnalyzeResponse;
import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import java.util.List;

class passiveAnalyzerThread implements Runnable {
    private Thread t;
    private int num=1;
    IHttpRequestResponse reqResp;
    List<IHttpRequestResponse> reqRespList=null;
    boolean checkResponse;
    IBurpExtenderCallbacks callbacks=BurpExtender.callbacks;
    private int max_response_length=250000;
    
    passiveAnalyzerThread( IHttpRequestResponse rr,boolean doResponse_based_tests){
        reqResp=rr;
        checkResponse=doResponse_based_tests;
        
    }
    passiveAnalyzerThread( List<IHttpRequestResponse> rrl,int tnum){
        num=tnum;
        reqRespList=rrl;
        
    }
    public void run() {
        if(reqRespList != null) {
            for (IHttpRequestResponse rr : reqRespList) {
                try {
                    if (rr.getRequest() != null) {
                        AnalyzeRequest(rr, -1);
                    }
                    if (rr.getResponse() != null) {
                        if (rr.getResponse().length <max_response_length) {
                            AnalyzeResponse(rr, -1);
                        }
                        else{
                        }

                    }
                }
                catch (Exception e) {
                    BurpExtender.output.println("***"+e.toString());
                }
            }
        } else {
            if (checkResponse) {
                PassiveAnalyzer.AnalyzeResponse(reqResp, -1);
            } else {
                PassiveAnalyzer.AnalyzeRequest(reqResp, -1);
            }
        }

    }
    
    public void start ()
    {
        t = new Thread (this, (num)+"");
        t.start ();
    }
    
}