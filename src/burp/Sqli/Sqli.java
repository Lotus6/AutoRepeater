package burp.Sqli;

import burp.Redirect.RedirectSettingsModel;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

public class Sqli {
    private JPanel sqliPanel;
    private SqliSettingsModel sqliModel;
    private JToggleButton activatedButton;

    public Sqli(boolean activated) {
        sqliModel = new SqliSettingsModel(activated);
        createUI();
    }

    public SqliSettingsModel getSettingsModel() {
        return sqliModel;
    }

    public void updateUIFromModel() {
        activatedButton.setSelected(sqliModel.isActivated());
        activatedButton.setText(sqliModel.isActivated() ? "Deactivate" : "Activate");
    }


    public JPanel getUI() {
        return sqliPanel;
    }

    private void createUI() {
        sqliPanel = new JPanel();
        sqliPanel.setLayout(new BoxLayout(sqliPanel, BoxLayout.Y_AXIS));
        sqliPanel.setBorder(new EmptyBorder(10, 10, 10, 10));

        // 创建一个 JToggleButton 来激活/停用 SSRF
        activatedButton = new JToggleButton("Activate");
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
        sqliPanel.add(activatedButton, c);


        JButton saveButton = new JButton("Save");
        saveButton.setAlignmentX(Component.LEFT_ALIGNMENT);
        sqliPanel.add(saveButton);

        saveButton.addActionListener(e -> {
            boolean newActivatedState = activatedButton.isSelected();
            sqliModel.setActivated(newActivatedState);
            // ... Rest of the code ...
        });

    }
}
