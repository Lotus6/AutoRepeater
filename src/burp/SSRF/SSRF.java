package burp.SSRF;

import burp.BurpExtender;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

public class SSRF {

    private JPanel ssrfPanel;
    private JTextField ceyeTokenTextField;
    private JTextField ceyeDnsLogTextField;
    private JToggleButton activatedButton;

    private SSRFSettingsModel settingsModel;

    public SSRF() {
        settingsModel = new SSRFSettingsModel("null", "null", false);
        createUI();
    }

    public void updateUIFromModel() {
        ceyeTokenTextField.setText(settingsModel.getCeyeToken());
        ceyeDnsLogTextField.setText(settingsModel.getCeyeDnsLog());
        activatedButton.setSelected(settingsModel.isActivated());
        activatedButton.setText(settingsModel.isActivated() ? "Deactivate" : "Activate");
    }

    public SSRFSettingsModel getSettingsModel() {
        return settingsModel;
    }

    public JPanel getUI() {
        return ssrfPanel;
    }

    private void createUI() {
        ssrfPanel = new JPanel();
        ssrfPanel.setLayout(new BoxLayout(ssrfPanel, BoxLayout.Y_AXIS));
        ssrfPanel.setBorder(new EmptyBorder(10, 10, 10, 10));

        activatedButton = new JToggleButton("Activate");

        // 创建一个 JToggleButton 来激活/停用 SSRF
        activatedButton.addChangeListener(e -> {
            if (activatedButton.isSelected()) {
                activatedButton.setText("Deactivate");
                // 在这里可以执行激活 SSRF 时的操作
            } else {
                activatedButton.setText("Activate");
                // 在这里可以执行停用 SSRF 时的操作
            }
        });

        // 将 activatedButton 添加到 ssrfPanel
        GridBagConstraints c = new GridBagConstraints();
        c.anchor = GridBagConstraints.FIRST_LINE_START;
        c.gridx = 0;
        c.weightx = 1;
        ssrfPanel.add(activatedButton, c);

        JPanel ceyeTokenPanel = new JPanel();
        ceyeTokenPanel.setLayout(new BoxLayout(ceyeTokenPanel, BoxLayout.Y_AXIS));
        ceyeTokenPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        JLabel ceyeTokenLabel = new JLabel("ceyetoken:");
        ceyeTokenPanel.add(ceyeTokenLabel);
        ceyeTokenTextField = new JTextField(10);
        ceyeTokenPanel.add(ceyeTokenTextField);

        ssrfPanel.add(ceyeTokenPanel);

        JPanel ceyeDnsLogPanel = new JPanel();
        ceyeDnsLogPanel.setLayout(new BoxLayout(ceyeDnsLogPanel, BoxLayout.Y_AXIS));
        ceyeDnsLogPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        JLabel ceyeDnsLogLabel = new JLabel("ceyednslog:");
        ceyeDnsLogPanel.add(ceyeDnsLogLabel);
        ceyeDnsLogTextField = new JTextField(10);
        ceyeDnsLogPanel.add(ceyeDnsLogTextField);

        ssrfPanel.add(ceyeDnsLogPanel);

        JButton saveButton = new JButton("Save");
        saveButton.setAlignmentX(Component.LEFT_ALIGNMENT);
        ssrfPanel.add(saveButton);

        saveButton.addActionListener(e -> {
            String ceyeToken = ceyeTokenTextField.getText();
            String ceyeDnsLog = ceyeDnsLogTextField.getText();
            boolean newActivatedState = activatedButton.isSelected();

            settingsModel.setCeyeToken(ceyeToken);
            settingsModel.setCeyeDnsLog(ceyeDnsLog);
            settingsModel.setActivated(newActivatedState);

            // ... Rest of the code ...
        });

    }


}
