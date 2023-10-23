/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package PassiveDigger;

import burp.BurpExtender;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.LinkedList;
import java.util.List;
import javax.swing.JMenuItem;

/**
 *
 * @author fatehi
 */
public class menuItem implements IContextMenuFactory{
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        final IHttpRequestResponse responses[] = invocation.getSelectedMessages();
        
        if(responses.length > 0){
            List<JMenuItem> ret = new LinkedList<JMenuItem>();
            final String passive_items;
            if(Passive_optionsPanel.getBaseReqRespList().size()==0){
                passive_items="Send target to Passive Digger";
            }
            else{
                passive_items="Add target to Passive Digger";
            }
            
            JMenuItem menuItem1 = new JMenuItem(passive_items);
            
            menuItem1.addActionListener(new ActionListener(){
                public void actionPerformed(ActionEvent arg0) {
                    //passive Header tab
                    if(arg0.getActionCommand().equals(passive_items)){
//                        PassivePanel.resetHeaderPanel();
                        for (IHttpRequestResponse rr : responses) {
                            BurpExtender.output.println("Adding "+rr.getHttpService().getHost()+":"+rr.getHttpService().getPort());
                            Passive_optionsPanel.AddToBaseReqResp(rr);
                        }
                    }
                }
            });
            ret.add(menuItem1);
            return(ret);
        }
        return null;
    }
    
}
