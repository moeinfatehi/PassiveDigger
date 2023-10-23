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
public class mainPanel extends JPanel
{
    public static JTabbedPane firstLevelTabs;
    private JPanel mainPanel;
    private JPanel passivepPanel;
    private JPanel helpPanel;
    
    static int passive_index=0;
    static int help_index=1;
    

    public mainPanel()
    {
        mainPanel = new JPanel(); //Creating the mainPanel JPanel
        passivepPanel=new PassivePanel();
        helpPanel=new HelpPanel();
        
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS)); //Setting Box layout, and set the direction to Y axis.
        firstLevelTabs = new JTabbedPane(); //Creating the additionalPanel JPanel     
        firstLevelTabs.add(passivepPanel,"Passive_Digger");
        firstLevelTabs.add(helpPanel,"Help");
        mainPanel.add(firstLevelTabs); //Adding panel2 into mainPanel
        this.setLayout(new GridLayout(1,1));
        this.add(mainPanel); //Setting mainPanel into JFrame

        this.setVisible(true); //Making JFrame Visible
    }

}
