/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package PassiveDigger;

import java.awt.GridLayout;
import javax.swing.BoxLayout;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;

/**
 *
 * @author "Moein Fatehi moein.fatehi@gmail.com"
 */
public class PassivePanel extends JPanel
{
    public static JTabbedPane PassiveTabs;
    private static JPanel PassivePanel;
    private static JPanel analyzerPanel;
    private static JPanel headersPanel;
    private static JPanel optionsPanel;
    
    static int analyzer_index=0;
    static int headers_index=1;
    static int options_index=2;

    public PassivePanel()
    {
        
        PassivePanel = new JPanel(); //Creating the PassivePanel JPanel
        analyzerPanel = new PassiveAnalyzer();
        headersPanel=new Passive_Headers();
        optionsPanel=new Passive_optionsPanel();
        
        PassivePanel.setLayout(new BoxLayout(PassivePanel, BoxLayout.Y_AXIS)); //Setting Box layout, and set the direction to Y axis.
        PassiveTabs = new JTabbedPane(); //Creating the additionalPanel JPanel     
        PassiveTabs.add(analyzerPanel,"Analyzer");
        PassiveTabs.add(headersPanel,"Headers");
        PassiveTabs.add(optionsPanel,"Options");
        PassivePanel.add(PassiveTabs); //Adding panel2 into PassivePanel
        this.setLayout(new GridLayout(1,1));
        this.add(PassivePanel); //Setting PassivePanel into JFrame

        this.setVisible(true); //Making JFrame Visible
    }
    
//    public static void resetHeaderPanel(){
//        analyzerPanel = new PassiveAnalyzer();
//        headersPanel=new Passive_Headers();
//        PassiveTabs.remove(analyzer_index);
//        PassiveTabs.add(analyzerPanel,"Analyzer",analyzer_index);
//        PassiveTabs.remove(headers_index);
//        PassiveTabs.add(headersPanel,"Headers",headers_index);
//        PassiveTabs.setSelectedIndex(0);
//    }

}
