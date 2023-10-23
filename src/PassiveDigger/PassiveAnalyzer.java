package PassiveDigger;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IParameter;
import burp.IRequestInfo;
import burp.IResponseInfo;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.ConcurrentModificationException;
import java.util.List;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JFrame;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;

/*
* To change this license header, choose License Headers in Project Properties.
* To change this template file, choose Tools | Templates
* and open the template in the editor.
*/

/**
 *
 * @author "Moein Fatehi moein.fatehi@gmail.com"
 */
public class PassiveAnalyzer extends javax.swing.JPanel implements burp.IHttpListener{
    private static String extension_name="Analyzer";
    private static Scanner sc;
    public static List<vulnerability> vulnerabilityList=new ArrayList<>();
    private static int EAR_avg=400;
    private static int ConcurrentModificationException=0;
    
    public static void AnalyzeRequest(IHttpRequestResponse reqResp,int toolFlag) {
        if(requestIsInScope(reqResp)){
            FindFileUploadInRequest(reqResp, toolFlag);
            ExtractEncodingsInRequest(reqResp);
            
        }
    }
    
    public static void AnalyzeResponse(IHttpRequestResponse reqResp, int toolFlag){
        try {
            if(requestIsInScope(reqResp)){
                SendToHeadersTab(reqResp);
                checkSQLInjection(reqResp);
                checkReflectedParams(reqResp);
                extractSensitiveDatas(reqResp);
                ExtractEncodingsInResponse(reqResp);
                checkMisconfiguration(reqResp);
                IResponseInfo respInfo = BurpExtender.callbacks.getHelpers().analyzeResponse(reqResp.getResponse());
                int status = respInfo.getStatusCode();
                if (status == 200) {
                    checkSensitiveFiles(reqResp, toolFlag);
                    checkLFI(reqResp, toolFlag);
                    checkDirectoryListing(reqResp, toolFlag);
                } else if (status / 100 == 3) {    //3xx
                    checkEAR(reqResp);  //Execution after redirection
                } else if (status / 100 == 4) {    //4xx
                    
                } else if (status / 100 == 5) {    //5xx
                    ExtractSensitiveDatasInErrors(reqResp);
                }
            }
            
        } catch (ConcurrentModificationException e) {
//            BurpExtender.output.println(new String(reqResp.getRequest()));
//            BurpExtender.output.println(Functions.getURL(reqResp));
//            BurpExtender.output.println(e.toString());
BurpExtender.output.println("ConcurrentModificationException: " + (++ConcurrentModificationException));
//BurpExtender.output.println(e.getMessage());
//BurpExtender.output.println(e.getCause());
//BurpExtender.output.println(e.getCause().toString());
        }
        
    }
    
    private static void FindSerializedInputInRequest(IHttpRequestResponse reqResp) {
        if(ruleIsEnabledToScan("request", "serialized")){
            String code=getRuleCode("request", "serialized");
            String req = new String(reqResp.getRequest());
            IRequestInfo reqInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(reqResp);
            String serialize_regex = "[a-z]:[0-9]+:[{\"][^{}]+[\"]+;";
            for (IParameter param : reqInfo.getParameters()) {
                String value_decoded = BurpExtender.callbacks.getHelpers().urlDecode(param.getValue());
                if (value_decoded.length() > 7) {
                    if (Functions.findRegex(serialize_regex, value_decoded) != null) { // param includes special chars and is not encoded.
                        vulnerability temp_vuln = new vulnerability(reqResp, param, "High", "-",code, "Serialized data found in input. Try PHP object injection)", false);
                        addToAnalyzerTable(temp_vuln);
                    }
                }
            }
        }
        
    }
    
    private static void updateAnalyseTabTitle() {
        PassivePanel.PassiveTabs.setTitleAt(PassivePanel.analyzer_index,"Analyzer ("+vulnerabilityList.size()+")");
//        BurpExtender.output.println("Analyzer size: "+vulnerabilityList.size());
    }
    
    private static void extractSensitiveDatas(IHttpRequestResponse reqResp) {
        ExtractEmailAddresses(reqResp);
        ExtractMobileNumbers(reqResp);
        FingerPrint(reqResp);
    }
    
    private static void ExtractSensitiveDatasInErrors(IHttpRequestResponse reqResp) {
        if(ruleIsEnabledToScan("response", "sensitive data in errors")){
            ExtractSourceCode(reqResp);
            ExtractLocalPathes(reqResp);
        }
    }
    
    private static void ExtractSourceCode(IHttpRequestResponse reqResp) {
        try {
            String code=getRuleCode("response", "sensitive data");
            IResponseInfo respInfo=BurpExtender.callbacks.getHelpers().analyzeResponse(reqResp.getResponse());
            String resp = new String(reqResp.getResponse()).substring(respInfo.getBodyOffset());
            List<String> regexes = Functions.ReadFile("analyzer_exceptionRegex");
            for (String regex : regexes) {
                List<String> matches = Functions.getAllMatches(regex, resp);
                for (String match : matches) {
                    vulnerability temp_vuln = new vulnerability(reqResp, null, "Low", "-", code,"Sensitive data disclosure in error ("+match+")", false);
                    addToAnalyzerTable(temp_vuln);
                }
            }
            
        } catch (IOException ex) {
            Logger.getLogger(PassiveAnalyzer.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private static void ExtractLocalPathes(IHttpRequestResponse reqResp) {
        String code=getRuleCode("response", "sensitive data");
        IResponseInfo respInfo=BurpExtender.callbacks.getHelpers().analyzeResponse(reqResp.getResponse());
        String resp = new String(reqResp.getResponse()).substring(respInfo.getBodyOffset());
        IRequestInfo reqInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(reqResp);
        String windows_regex = "([a-z]:\\\\|\\\\\\\\)(\\\\?[a-z_\\-\\s0-9\\.]+\\\\)+([a-z_\\-\\s0-9\\.]+)\\.([a-z_\\-0-9]{2,4})";
        String unix_regex = "(?i)\\/((var|opt|home)\\/)([a-z_\\- 0-9\\.]+\\/)+[a-z_\\- 0-9\\.]+(\\.[a-z0-9]{2,5})?";
        
        List<String> matches=Functions.getAllMatches(windows_regex, resp) ;
        for (String match : matches) {
            vulnerability temp_vuln = new vulnerability(reqResp, null, "Informational", "-",code,"Local path '"+match+"' found in error", false);
            addToAnalyzerTable(temp_vuln);
        }
        
        matches=Functions.getAllMatches(unix_regex, resp) ;
        for (String match : matches) {
            vulnerability temp_vuln = new vulnerability(reqResp, null,code,"Informational", "-", "Unix-based local path '"+match+"' found in error", false);
            addToAnalyzerTable(temp_vuln);
        }
    }
    
    private static void FingerPrint(IHttpRequestResponse reqResp) {
        if(ruleIsEnabledToScan("response", "fingerprint")){
            String code=getRuleCode("response", "fingerprint");
            IResponseInfo respInfo=BurpExtender.callbacks.getHelpers().analyzeResponse(reqResp.getResponse());
            for(String header:respInfo.getHeaders()){
                if(header.startsWith("Server:")){
                    vulnerability temp_vuln = new vulnerability(reqResp, null, "Informational", "-", code,"Server name '" + getHeaderValue(header) + "' extracted from "+getHeaderName(header)+" header", true);
                    addToAnalyzerTable(temp_vuln);
                }
                if(header.startsWith("X-Powered-By:")){
                    vulnerability temp_vuln = new vulnerability(reqResp, null, "Informational", "-", code,"Web application framework '" + getHeaderValue(header) + "' extracted from "+getHeaderName(header)+" header", true);
                    addToAnalyzerTable(temp_vuln);
                }
                if (header.startsWith("X-AspNet-Version:")) {
                    vulnerability temp_vuln = new vulnerability(reqResp, null, "Informational", "-", code,"ASP.net version '" + getHeaderValue(header) + "' extracted from "+getHeaderName(header)+" header", true);
                    addToAnalyzerTable(temp_vuln);
                }
            }
        }
        
    }
    
    private static void CheckCookieFlags(IHttpRequestResponse reqResp) {
        if(ruleIsEnabledToScan("response", "cookie flags")){
            String code=getRuleCode("response", "cookie flags");
            IResponseInfo respInfo=BurpExtender.callbacks.getHelpers().analyzeResponse(reqResp.getResponse());
            for(String header:respInfo.getHeaders()){
                if(header.startsWith("Set-Cookie:")){
                    String newCookie=getHeaderValue(header);
                    if(!newCookie.contains("HttpOnly")){
                        vulnerability temp_vuln = new vulnerability(reqResp, null, "Low", "-", code,"Cookie '" + newCookie.substring(0,newCookie.indexOf("="))+ "' is without HttpOnly flag set.", true);
                        addToAnalyzerTable(temp_vuln);
                    }
                    if(!newCookie.contains("Secure")){
                        if(reqResp.getHttpService().getProtocol().equalsIgnoreCase("https")){
                            vulnerability temp_vuln = new vulnerability(reqResp, null, "Low", "-", code,"Cookie '" + newCookie.substring(0,newCookie.indexOf("="))+ "' is without Secure flag set in HTTPS mode.", true);
                            addToAnalyzerTable(temp_vuln);
                        }
                        
                    }
                    
                }
            }
        }
        
    }
    
    private static String getHeaderName(String header) {
        Scanner sc=new Scanner(header);
        sc.useDelimiter(":");
        return sc.next();
    }
    
    private static String getHeaderValue(String header) {
        Scanner sc=new Scanner(header);
        sc.useDelimiter(":");
        try {
            sc.next();
            String value = sc.next();
            if (value.startsWith(" ")) {
                value = value.substring(1);
            }
            return value;
        } catch (Exception e) {
            return "";
        }
    }
    
    private static void checkMisconfiguration(IHttpRequestResponse reqResp) {
        CheckCookieFlags(reqResp);
    }
    
    private static void ExtractEncodingsInRequest(IHttpRequestResponse reqResp) {
        FindSerializedInputInRequest(reqResp);
        FindBase64InRequest(reqResp);
    }
    
    private static void FindBase64InRequest(IHttpRequestResponse reqResp) {
        if(ruleIsEnabledToScan("request", "base64")){
            String code=getRuleCode("response", "cookie flags");
            String req = BurpExtender.callbacks.getHelpers().urlDecode(new String(reqResp.getRequest()));
            IRequestInfo reqInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(reqResp);
            String base64_regex = "[A-Za-z0-9+]{4}(?:[A-Za-z0-9+\\/]{4}){2,}(?:[A-Za-z0-9+\\/]{2}==|[A-Za-z0-9+\\/]{3}=)?";
            for (IParameter parameter : reqInfo.getParameters()) {
                try {
                    String b64 = Functions.findRegex(base64_regex, parameter.getValue());
                    if (b64 != null) {
                        if (!Functions.base64Decode(b64).equals(b64) && !Functions.base64Decode(b64).equals("encrypted_Base64")) {
                            vulnerability temp_vuln = new vulnerability(reqResp, parameter, "Informational", "-", code,"Base64 encoded data in request, decoded to: '" + Functions.base64Decode(b64) + "' (" + parameter.getName() + " " + Functions.getParamType(parameter.getType()) + " parameter)", true);
                            addToAnalyzerTable(temp_vuln);
                        }
                    }
                } catch (Exception e) {
//                    BurpExtender.output.println("****1");
                }
                
            }
            for (String header : reqInfo.getHeaders()) {
                try {
                    
                    List<String> matches = Functions.getAllMatches(base64_regex, getHeaderValue(header));
                    for (String match : matches) {
                        if (!Functions.base64Decode(match).equals(match) && !Functions.base64Decode(match).equals("encrypted_Base64")) {
                            vulnerability temp_vuln = new vulnerability(reqResp, null, "Informational", "-", code,"Base64 encoded data in request, decoded to: '" + Functions.base64Decode(match) + "' (" + getHeaderName(header) + " header)", true);
                            addToAnalyzerTable(temp_vuln);
                        }
                        
                    }
                } catch (Exception e) {
                    BurpExtender.output.println(e.toString());
                }
                
            }
            List<String> matches=Functions.getAllMatches(base64_regex, req) ;
            for (String match : matches) {
                if(!Functions.base64Decode(match).equals(match)&&!Functions.base64Decode(match).equals("encrypted_Base64")){
                    vulnerability temp_vuln = new vulnerability(reqResp, null, "Informational", "-", code,"Base64 encoded data in request, decoded to: '" + Functions.base64Decode(match) + "'", true);
                    addToAnalyzerTable(temp_vuln);
                }
                
            }
        }
        
    }
    
    private static void ExtractEncodingsInResponse(IHttpRequestResponse reqResp) {
        FindBase64InResponse(reqResp);
    }
    
    private static void FindBase64InResponse(IHttpRequestResponse reqResp) {
        if(ruleIsEnabledToScan("response", "base64")){
            String code=getRuleCode("response", "base64");
            IResponseInfo respInfo=BurpExtender.callbacks.getHelpers().analyzeResponse(reqResp.getResponse());
            String resp = BurpExtender.callbacks.getHelpers().urlDecode(new String(reqResp.getResponse()));
            String base64_regex = "[A-Za-z0-9+]{4}(?:[A-Za-z0-9+\\/]{4}){2,}(?:[A-Za-z0-9+\\/]{2}==|[A-Za-z0-9+\\/]{3}=)?";
            List<String> matches=Functions.getAllMatches(base64_regex, resp) ;
            for (String match : matches) {
                if(!Functions.base64Decode(match).equals(match)&&!Functions.base64Decode(match).equals("encrypted_Base64")){
                    vulnerability temp_vuln = new vulnerability(reqResp, null, "Informational", "-", code,"Base64 encoded data in response, decoded to: '" + Functions.base64Decode(match) + "'", true);
                    addToAnalyzerTable(temp_vuln);
                }
            }
        }
    }
    
    private static void SendToHeadersTab(IHttpRequestResponse reqResp) {
        Passive_Headers.addToHeadersTable(reqResp);
    }
    
    private static boolean ruleIsEnabledToScan(String reqOrResp, String rule) {
        switch (reqOrResp){
            case "request":
                for (int i = 0; i < Passive_optionsPanel.options_request_table.getRowCount(); i++) {
                    if(Passive_optionsPanel.options_request_table.getValueAt(i, 2).toString().toLowerCase().contains(rule)){
                        return getRuleStatus(Passive_optionsPanel.options_request_table, i);
//                        try {   // When it is not enabled, it returns exception.
//                            return (boolean)Passive_optionsPanel.options_request_table.getValueAt(i, 0);
//                        } catch (Exception e) {
//                            return false;
//                        }
                    }
                }
                return false;
            case "response":
                for (int i = 0; i < Passive_optionsPanel.options_response_table.getRowCount(); i++) {
                    if(Passive_optionsPanel.options_response_table.getValueAt(i, 2).toString().toLowerCase().contains(rule)){
                        return getRuleStatus(Passive_optionsPanel.options_response_table, i);
//                        try {   // When it is not enabled, it returns null! (ty to enable and disable in netbeans GUI (in table contents part).
//                            return (boolean)Passive_optionsPanel.options_response_table.getValueAt(i, 0);
//                        } catch (Exception e) {
//                            return false;
//                        }
                    }
                }
                return false;
        }
        return false;
    }
    
    private static String getRuleCode(String reqOrResp, String rule) {
        switch (reqOrResp){
            case "request":
                for (int i = 0; i < Passive_optionsPanel.options_request_table.getRowCount(); i++) {
                    if(Passive_optionsPanel.options_request_table.getValueAt(i, 2).toString().toLowerCase().contains(rule)){
                        return Passive_optionsPanel.options_request_table.getValueAt(i, 1).toString();
                    }
                }
            case "response":
                for (int i = 0; i < Passive_optionsPanel.options_response_table.getRowCount(); i++) {
                    if(Passive_optionsPanel.options_response_table.getValueAt(i, 2).toString().toLowerCase().contains(rule)){
                        return Passive_optionsPanel.options_response_table.getValueAt(i, 1).toString();
                    }
                }
        }
        return null;
    }
    
    public static boolean getRuleStatus(JTable table,int row) {
        if((boolean)table.getValueAt(row, 0)==true){
            return true;
        }
        // When it is not enabled, it returns null! (ty to enable and disable in netbeans GUI (in table contents part)
        return false;
    }
    
    
    /**
     * Creates new form HeadersPanel
     */
    public PassiveAnalyzer() {
        initComponents();
        initialize();
    }
    
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        PassiveAbalyzerPanel = new javax.swing.JPanel();
        jScrollPane1 = new javax.swing.JScrollPane();
        AnalyzerTable = new javax.swing.JTable();
        loadFromHistoryButton = new javax.swing.JButton();
        FalsePositiveButton = new javax.swing.JButton();
        loadFromSitemap = new javax.swing.JButton();
        jLabel2 = new javax.swing.JLabel();
        FalsePositiveButton1 = new javax.swing.JButton();
        FalsePositiveButton2 = new javax.swing.JButton();
        FalsePositiveButton3 = new javax.swing.JButton();

        AnalyzerTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {
                "#", "Severity", "URL", "Parameter", "Type", "Code", "Description"
            }
        ) {
            Class[] types = new Class [] {
                java.lang.Integer.class, java.lang.Object.class, java.lang.String.class, java.lang.String.class, java.lang.String.class, java.lang.Object.class, java.lang.String.class
            };
            boolean[] canEdit = new boolean [] {
                false, false, false, false, false, false, false
            };

            public Class getColumnClass(int columnIndex) {
                return types [columnIndex];
            }

            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return canEdit [columnIndex];
            }
        });
        AnalyzerTable.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                AnalyzerTableMouseClicked(evt);
            }
        });
        jScrollPane1.setViewportView(AnalyzerTable);
        if (AnalyzerTable.getColumnModel().getColumnCount() > 0) {
            AnalyzerTable.getColumnModel().getColumn(0).setPreferredWidth(40);
            AnalyzerTable.getColumnModel().getColumn(0).setMaxWidth(60);
            AnalyzerTable.getColumnModel().getColumn(1).setPreferredWidth(100);
            AnalyzerTable.getColumnModel().getColumn(1).setMaxWidth(150);
            AnalyzerTable.getColumnModel().getColumn(2).setPreferredWidth(200);
            AnalyzerTable.getColumnModel().getColumn(2).setMaxWidth(400);
            AnalyzerTable.getColumnModel().getColumn(3).setPreferredWidth(100);
            AnalyzerTable.getColumnModel().getColumn(3).setMaxWidth(200);
            AnalyzerTable.getColumnModel().getColumn(4).setPreferredWidth(70);
            AnalyzerTable.getColumnModel().getColumn(4).setMaxWidth(100);
            AnalyzerTable.getColumnModel().getColumn(5).setPreferredWidth(70);
            AnalyzerTable.getColumnModel().getColumn(5).setMaxWidth(80);
            AnalyzerTable.getColumnModel().getColumn(6).setPreferredWidth(300);
        }

        loadFromHistoryButton.setText("Load From History");
        loadFromHistoryButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                loadFromHistoryButtonActionPerformed(evt);
            }
        });

        FalsePositiveButton.setText("False positive");
        FalsePositiveButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                FalsePositiveButtonActionPerformed(evt);
            }
        });

        loadFromSitemap.setText("Load From Sitemap");
        loadFromSitemap.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                loadFromSitemapActionPerformed(evt);
            }
        });

        jLabel2.setText("(Double click for details)");

        FalsePositiveButton1.setText("-> Repeater");
        FalsePositiveButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                FalsePositiveButton1ActionPerformed(evt);
            }
        });

        FalsePositiveButton2.setText("-> Intruder");
        FalsePositiveButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                FalsePositiveButton2ActionPerformed(evt);
            }
        });

        FalsePositiveButton3.setText("Open");
        FalsePositiveButton3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                FalsePositiveButton3ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout PassiveAbalyzerPanelLayout = new javax.swing.GroupLayout(PassiveAbalyzerPanel);
        PassiveAbalyzerPanel.setLayout(PassiveAbalyzerPanelLayout);
        PassiveAbalyzerPanelLayout.setHorizontalGroup(
            PassiveAbalyzerPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(PassiveAbalyzerPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(PassiveAbalyzerPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(PassiveAbalyzerPanelLayout.createSequentialGroup()
                        .addComponent(loadFromHistoryButton, javax.swing.GroupLayout.PREFERRED_SIZE, 147, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(loadFromSitemap, javax.swing.GroupLayout.PREFERRED_SIZE, 153, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jLabel2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                    .addGroup(PassiveAbalyzerPanelLayout.createSequentialGroup()
                        .addGroup(PassiveAbalyzerPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(FalsePositiveButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(FalsePositiveButton2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(FalsePositiveButton1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(FalsePositiveButton3, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 583, Short.MAX_VALUE)))
                .addContainerGap())
        );
        PassiveAbalyzerPanelLayout.setVerticalGroup(
            PassiveAbalyzerPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(PassiveAbalyzerPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(PassiveAbalyzerPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(loadFromHistoryButton)
                    .addComponent(loadFromSitemap)
                    .addComponent(jLabel2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(PassiveAbalyzerPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(PassiveAbalyzerPanelLayout.createSequentialGroup()
                        .addComponent(FalsePositiveButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(FalsePositiveButton3)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(FalsePositiveButton1)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(FalsePositiveButton2)
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addComponent(jScrollPane1))
                .addContainerGap())
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(PassiveAbalyzerPanel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(PassiveAbalyzerPanel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );
    }// </editor-fold>//GEN-END:initComponents

    private void loadFromSitemapActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_loadFromSitemapActionPerformed
        if(Passive_optionsPanel.targetIsLoaded()){
            for (IHttpRequestResponse rr : Passive_optionsPanel.getBaseReqRespList()) {
                IHttpService serv=rr.getHttpService();
                String prefix=serv.getProtocol()+"://"+serv.getHost();
                if(serv.getPort()!=80){
                    prefix+=":"+serv.getPort();
                }
                AnalyzeManyRequests(BurpExtender.callbacks.getSiteMap(prefix));
            }
        }
    }//GEN-LAST:event_loadFromSitemapActionPerformed

    private void FalsePositiveButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_FalsePositiveButtonActionPerformed
        int[]rows=AnalyzerTable.getSelectedRows();
        
        for(int i=rows.length-1;i>=0;i--){
            int thisInd=AnalyzerTable.convertRowIndexToModel(rows[i]);  //to delete correctly in a sorted table
            removeAnalyzerTableRow(thisInd);
        }
        updateRowNumbers();
        updateAnalyseTabTitle();
    }//GEN-LAST:event_FalsePositiveButtonActionPerformed

    private void loadFromHistoryButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_loadFromHistoryButtonActionPerformed
        if(Passive_optionsPanel.targetIsLoaded()){
            AnalyzeManyRequests(BurpExtender.callbacks.getProxyHistory());
        }
    }//GEN-LAST:event_loadFromHistoryButtonActionPerformed

    private void AnalyzerTableMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_AnalyzerTableMouseClicked
        if(evt.getClickCount()==2){
            int index=AnalyzerTable.getSelectedRow();
            int ind=(int)AnalyzerTable.getValueAt(index, 0)-1;
            if(vulnerabilityList.get(ind)!=null){
                try {
                    vulnerability vuln = vulnerabilityList.get(ind);
                    vulnerabilityForm.setReqResp(vuln.reqResp);
                    vulnerabilityForm vf = new vulnerabilityForm();
                    vf.setReqResp(vuln.reqResp);
                    vf.descriptionField.setText(vuln.getDescription());
                    vf.URLField.setText(Functions.getURL(vuln.reqResp).toString());
                    vf.severityField.setText(vuln.severity);
                    vf.cvssField.setText(vuln.cvss);
                    if(vuln.param!=null){
                        vf.paramField.setText(vuln.param.getName());
                        vf.paramType_Field.setText(Functions.getParamType(vuln.param.getType()));
                    }
                    vf.setSeverityColor();
                    vf.setLocationRelativeTo(null);
                    vf.setDefaultCloseOperation(JFrame.HIDE_ON_CLOSE);
                    vf.setSeverityColor();
                    vf.tabs.setSelectedIndex(0);
                    vf.setVisible(true);
                } catch (Exception e) {
                    BurpExtender.output.println("*******"+e.toString());
                }
                
            }
        }
    }//GEN-LAST:event_AnalyzerTableMouseClicked

    private void FalsePositiveButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_FalsePositiveButton1ActionPerformed
        int[]rows=AnalyzerTable.getSelectedRows();
        
        for(int i=0;i<rows.length;i++){
            int thisInd=AnalyzerTable.convertRowIndexToModel(rows[i]);  //to delete correctly in a sorted table
            IHttpService serv = vulnerabilityList.get(thisInd).getReqResp().getHttpService();
            String tabname="";
            tabname=vulnerabilityList.get(thisInd).getCode();
            String param="";
            if(vulnerabilityList.get(thisInd).param!=null){
                param=vulnerabilityList.get(thisInd).param.getName();
                if(param.length()>8){
                    param=param.substring(0,8);
                }
                tabname=tabname+"("+param+")";
            }
            
            
            BurpExtender.callbacks.sendToRepeater(serv.getHost(),serv.getPort(), (serv.getProtocol().equalsIgnoreCase("HTTPS"))?true:false, vulnerabilityList.get(thisInd).getReqResp().getRequest(),tabname);
        }
        updateRowNumbers();
        updateAnalyseTabTitle();
    }//GEN-LAST:event_FalsePositiveButton1ActionPerformed

    private void FalsePositiveButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_FalsePositiveButton2ActionPerformed
        int[]rows=AnalyzerTable.getSelectedRows();
        
        for(int i=0;i<rows.length;i++){
            int thisInd=AnalyzerTable.convertRowIndexToModel(rows[i]);  //to delete correctly in a sorted table
            IHttpService serv = vulnerabilityList.get(thisInd).getReqResp().getHttpService();
            BurpExtender.callbacks.sendToIntruder(serv.getHost(),serv.getPort(), (serv.getProtocol().equalsIgnoreCase("HTTPS"))?true:false, vulnerabilityList.get(thisInd).getReqResp().getRequest());
        }
        updateRowNumbers();
        updateAnalyseTabTitle();
    }//GEN-LAST:event_FalsePositiveButton2ActionPerformed

    private void FalsePositiveButton3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_FalsePositiveButton3ActionPerformed
        int[]rows=AnalyzerTable.getSelectedRows();
        for(int i=0;i<rows.length;i++){
            int thisInd=AnalyzerTable.convertRowIndexToModel(rows[i]);  //to delete correctly in a sorted table
            URL url = BurpExtender.callbacks.getHelpers().analyzeRequest(vulnerabilityList.get(thisInd).getReqResp()).getUrl();
            Functions.openWebpage(url);
        }
    }//GEN-LAST:event_FalsePositiveButton3ActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    public static javax.swing.JTable AnalyzerTable;
    private javax.swing.JButton FalsePositiveButton;
    private javax.swing.JButton FalsePositiveButton1;
    private javax.swing.JButton FalsePositiveButton2;
    private javax.swing.JButton FalsePositiveButton3;
    private javax.swing.JPanel PassiveAbalyzerPanel;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JButton loadFromHistoryButton;
    private javax.swing.JButton loadFromSitemap;
    // End of variables declaration//GEN-END:variables
    
    
    public static void removeAnalyzerTableRow(int i) {
        BurpExtender.output.println("Row "+i+" removed.");
        DefaultTableModel AnalyzerModel=(DefaultTableModel)AnalyzerTable.getModel();
        AnalyzerModel.removeRow(i);
        vulnerabilityList.remove(i);
        Functions.updateRowNumbers(AnalyzerTable);
        updateAnalyseTabTitle();
    }
    
    private void initialize() {
        TableRowSorter<TableModel> sorter = new TableRowSorter<TableModel>(AnalyzerTable.getModel());
        AnalyzerTable.setRowSorter(sorter);
    }
    
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if(requestIsInScope(messageInfo)){
            if(messageIsRequest){
                passiveAnalyzerThread pat = new passiveAnalyzerThread(messageInfo, false);  //false: do not test response-based tests
                pat.start();
            } else if (!messageIsRequest) {
                passiveAnalyzerThread pat = new passiveAnalyzerThread(messageInfo, true);  //True: test response-based tests
                pat.start();
            }
        }
        
        
    }
    
    public static String getToolName (int toolFlag){
        switch (toolFlag){
            case IBurpExtenderCallbacks.TOOL_TARGET:
                return "Target";
            case IBurpExtenderCallbacks.TOOL_PROXY:
                return "Proxy";
            case IBurpExtenderCallbacks.TOOL_SPIDER:
                return "Spider";
            case IBurpExtenderCallbacks.TOOL_SCANNER:
                return "Scanner";
            case IBurpExtenderCallbacks.TOOL_INTRUDER:
                return "Intruder";
            case IBurpExtenderCallbacks.TOOL_REPEATER:
                return "Repeater";
            case IBurpExtenderCallbacks.TOOL_SEQUENCER:
                return "Sequencer";
            case IBurpExtenderCallbacks.TOOL_DECODER:
                return "Decoder";
            case IBurpExtenderCallbacks.TOOL_COMPARER:
                return "Comparer";
            case IBurpExtenderCallbacks.TOOL_EXTENDER:
                return "Extender";
            default:
                return "-";
        }
    }
    
    private static void checkSensitiveFiles(IHttpRequestResponse reqResp, int toolFlag) {
        if(ruleIsEnabledToScan("response", "sensitive files")){
            String code=getRuleCode("response", "sensitive files");
            try {
                IRequestInfo reqInfo=BurpExtender.callbacks.getHelpers().analyzeRequest(reqResp);
                IResponseInfo respInfo=BurpExtender.callbacks.getHelpers().analyzeResponse(reqResp.getResponse());
                String path=reqInfo.getUrl().getPath();
                List<String> sensitive_Files=Functions.ReadFile("analyzer_sensitive_files");
                for (String sensitive_File : sensitive_Files) {
                    if(path.equals(sensitive_File)){
                        vulnerability temp_vuln=new vulnerability(reqResp, null, "Informational", "-", code,"Sensitive file or Dir found: "+sensitive_File,true);
                        addToAnalyzerTable(temp_vuln);
                        break;
                    }
                }
            } catch (IOException ex) {
                Logger.getLogger(PassiveAnalyzer.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        
    }
    
    private static void addToAnalyzerTable(vulnerability vuln) {
        if(IssueIsUnique(vuln)) {
            DefaultTableModel analyzerModel = (DefaultTableModel) AnalyzerTable.getModel();
            IRequestInfo reqInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(vuln.reqResp);
            String url = reqInfo.getUrl().toString();
            Object rowData[];
            String description=vuln.getDescription();
            if(description.length()>120){
                description=description.substring(0,117)+"...";
            }
            if(vuln.param!=null){
                rowData = new Object[]{AnalyzerTable.getRowCount() + 1, vuln.severity,url, vuln.param.getName(), Functions.getParamType(vuln.param.getType()),vuln.code,description};
            }
            else{
                rowData = new Object[]{AnalyzerTable.getRowCount() + 1, vuln.severity,url, "-", "-",vuln.code,description};
            }
            
            analyzerModel.addRow(rowData);
            vulnerabilityList.add(vuln);
            updateAnalyseTabTitle();
            
        }
        
    }
    
    private static void checkLFI(IHttpRequestResponse reqResp, int toolFlag) {
        if(ruleIsEnabledToScan("response", "lfi")){
            String code=getRuleCode("response", "lfi");
            IRequestInfo reqInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(reqResp);
            for (IParameter param : reqInfo.getParameters()) {
                String mat=Functions.findRegex("^[\\w,\\s-]+\\.[A-Za-z]{2,4}$", param.getValue());
                if(mat!=null) {
                    vulnerability temp_vuln = new vulnerability(reqResp, param, "High", "-", code,"Possible LFI vulnerability (Trying to read " + param.getValue() + " file)", false);
                    addToAnalyzerTable(temp_vuln);
                }
            }
        }
    }
    
    private static void FindFileUploadInRequest(IHttpRequestResponse reqResp, int toolFlag) {
        if(ruleIsEnabledToScan("request","upload")){
            String code=getRuleCode("request","upload");
            IRequestInfo reqInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(reqResp);
            for (IParameter param : reqInfo.getParameters()) {
                if(param.getType()==IParameter.PARAM_MULTIPART_ATTR&&param.getName()=="filename"){
                    vulnerability temp_vuln = new vulnerability(reqResp, param, "Informational", "-", code,"File upload functionality found.", false);
                    addToAnalyzerTable(temp_vuln);
                    break;
                }
            }
        }
    }
    
    private static boolean IssueIsUnique(vulnerability vuln) {
        if(vuln.server_oneTime){
            for (vulnerability vuln2 : vulnerabilityList) {
                if(vuln.equalsLevel1(vuln2)){
                    return false;
                }
            }
            return true;
        }
        else{
            for (vulnerability vuln2 : vulnerabilityList) {
                if(vuln.equalsLevel2(vuln2)){
                    return false;
                }
            }
            return true;
        }
    }
    
    private static void checkDirectoryListing(IHttpRequestResponse reqResp, int toolFlag) {
        if(ruleIsEnabledToScan("response", "indexing")){
            String code=getRuleCode("response", "indexing");
            String resp=new String(reqResp.getResponse());
            if (resp.contains("<title>Index of /")){
                if(resp.contains("<a href=\"?C=N;O=D\">Name")){
                    if(!Functions.getURL(reqResp).toString().endsWith("C=N;O=A")) { //avoid listing directory listing of a directory twice
                        vulnerability temp_vuln = new vulnerability(reqResp, null, "Low", "(AV:N/AC:L/Au:N/C:P/I:N/A:N)", code,"Directory indexing/browsing", false);
                        addToAnalyzerTable(temp_vuln);
                    }
                }
            }
        }
        
    }
    
    private static void updateRowNumbers(){
        DefaultTableModel AnalyzerModel=(DefaultTableModel)AnalyzerTable.getModel();
        for (int i = 0; i < AnalyzerTable.getRowCount(); i++) {
            AnalyzerModel.setValueAt(i+1, i, 0);
        }
    }
    
    private static void checkEAR(IHttpRequestResponse reqResp) {
        if(ruleIsEnabledToScan("response", "execution after redirection")){
            String code=getRuleCode("response", "execution after redirection");
            IResponseInfo respInfo=BurpExtender.callbacks.getHelpers().analyzeResponse(reqResp.getResponse());
            int content_length=reqResp.getResponse().length-respInfo.getBodyOffset();
            
            if(content_length > EAR_avg) {
                vulnerability temp_vuln = new vulnerability(reqResp, null, "Medium", "(AV:N/AC:L/Au:N/C:P/I:N/A:N)", code,"Possible Execution After Redirection (EAR)", false);
                addToAnalyzerTable(temp_vuln);
            }
        }
        
    }
    
    private static void checkSQLInjection(IHttpRequestResponse reqResp) {
        if(ruleIsEnabledToScan("response", "sql")){
            String code=getRuleCode("response", "sql");
            try {
                List<String> sql_errors_regex = Functions.ReadFile("analyser_sqlErrors");
                String resp = new String(reqResp.getResponse());
                for (String error : sql_errors_regex) {
                    String mat = Functions.findRegex(error, resp);
                    if (mat != null) {
                        vulnerability temp_vuln = new vulnerability(reqResp, null, "High", "-", code,"Possible SQL injection (Error occured: " + mat + ")", false);
                        addToAnalyzerTable(temp_vuln);
                        break;
                    }
                }
            } catch (Exception e) {
            }
        }
        
    }
    
    private static void checkReflectedParams(IHttpRequestResponse reqResp) {
        if(ruleIsEnabledToScan("response", "xss")){
            String code=getRuleCode("response", "xss");
            try {
                String resp = new String(reqResp.getResponse());
                IRequestInfo reqInfo=BurpExtender.callbacks.getHelpers().analyzeRequest(reqResp);
                String xss_regex = "(<|>|'|\")+";
                List<String> list=Functions.ReadFile("xss_falsePositive_Values");
                boolean skip=false;
                for (IParameter param : reqInfo.getParameters()) {
                    String value_decoded=BurpExtender.callbacks.getHelpers().urlDecode(param.getValue());
                    for (String string : list) {    //If value is in "xss_falsePositive_Values" file
                        if(value_decoded.equalsIgnoreCase(string)){
                            skip=true;
                            break;
                        }
                    }
                    int repeat = findRepeatCount(resp, value_decoded);
                    if (value_decoded.length() > 5 && repeat > 0 && !skip) {
                        if (Functions.findRegex(xss_regex, value_decoded) != null) { // param includes special chars and is not encoded.
                            vulnerability temp_vuln = new vulnerability(reqResp, param, "High", "-", code,"Possible XSS in '" + param.getName() + "' parameter ( reflection count: " + repeat + ")", false);
                            addToAnalyzerTable(temp_vuln);
                        } else {    //It is just reflected and we're not sure about encoding
                            vulnerability temp_vuln = new vulnerability(reqResp, param, "Informational", "-", code,"Parameter '" + param.getName() + "' reflected in response, check for XSS and HTML injection.( reflection count: " + repeat + ")", false);
                            addToAnalyzerTable(temp_vuln);
                        }
                    }
                }
            } catch (IOException ex) {
                BurpExtender.output.println("checkReflectedParams exception");
                Logger.getLogger(PassiveAnalyzer.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        
    }
    
    private static void ExtractEmailAddresses(IHttpRequestResponse reqResp) {
        if(ruleIsEnabledToScan("response", "email")){
            String code=getRuleCode("response", "email");
            IResponseInfo respInfo=BurpExtender.callbacks.getHelpers().analyzeResponse(reqResp.getResponse());
            String resp = new String(reqResp.getResponse()).substring(respInfo.getBodyOffset());
            String email_regex = "(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}";
            List<String> matches=Functions.getAllMatches(email_regex, resp) ;
            for (String match : matches) {
                vulnerability temp_vuln = new vulnerability(reqResp, null, "Informational", "-", code,"Found email address '"+match+"' in response", true);
                addToAnalyzerTable(temp_vuln);
            }
        }
        
    }
    
    private static void ExtractMobileNumbers(IHttpRequestResponse reqResp) {
        if(ruleIsEnabledToScan("response", "phone")){
            String code=getRuleCode("response", "phone");
            IResponseInfo respInfo=BurpExtender.callbacks.getHelpers().analyzeResponse(reqResp.getResponse());
            String resp = new String(reqResp.getResponse()).substring(respInfo.getBodyOffset());
            String mobile_regex = "(\\+[1-9]{1,3}[ \\-]?|0+)[1-9]\\d{9,}";
            
            List<String> matches=Functions.getAllMatches(mobile_regex, resp) ;
            for (String match : matches) {
                BurpExtender.output.print("Number "+match);
                String pureNumber=match.replaceAll(" ", "");
                pureNumber=pureNumber.replace("-", "");
                pureNumber=pureNumber.replace("+", "");
                if(pureNumber.length()<=13 && pureNumber.length()>=11){ //Min accepted: 09101234567:11    max accepted: +912-8087339090 (pureNumber:13)
                    vulnerability temp_vuln = new vulnerability(reqResp, null, "Informational", "-", code,"Found mobile number '" + match + "' in response", true);
                    addToAnalyzerTable(temp_vuln);
                }
            }
        }
    }
    
    private static int findRepeatCount(String resp, String value) {
        int ind = 0;
        int cnt = 0;
        try {
        } catch (Exception e) {
            BurpExtender.output.println(e.toString());
        }
        
        while (true) {
            int pos = resp.indexOf(value, ind);
            if (pos<ind) {
                break;
            }
            else{
            }
            cnt++;
            ind = pos + 1; // Advance by second.length() to avoid self repetitions
        }
        return cnt;
    }
    
    private void AnalyzeManyRequests(IHttpRequestResponse[] requests) {
        int length = requests.length;
        int threads=1;
        int each=length/threads+1;
        int end=0;
        for (int i = 0; i < threads; i++) {
            end = Math.min((i + 1) * each, length);
            List<IHttpRequestResponse> temp = new ArrayList<>();
            for (int j = i * each; j < end; j++) {
                if(requestIsInScope(requests[j])){
                    temp.add(requests[j]);
                }
            }
            if (temp != null) {
                passiveAnalyzerThread pat = new passiveAnalyzerThread(temp, (i + 1));
                pat.start();
            }
        }
    }
    
    public static boolean requestIsInScope(IHttpRequestResponse reqResp) {
        if(Passive_optionsPanel.targetIsLoaded()){
            for (IHttpRequestResponse rr : Passive_optionsPanel.getBaseReqRespList()) {
                if(reqResp.getHttpService().getHost().equals(rr.getHttpService().getHost())){
                    if(reqResp.getHttpService().getPort()==rr.getHttpService().getPort()){
                        return true;
                    }
                }
            }
        }
        return false;
    }
}