package burp;

import burp.Conditions.Condition;
import burp.Conditions.ConditionTableModel;
import burp.Conditions.Conditions;
import burp.Filter.Filter;
import burp.Filter.FilterTableModel;
import burp.Filter.Filters;
import burp.Highlighter.Highlighter;
import burp.Highlighter.HighlighterTableModel;
import burp.Highlighter.HighlighterUITableModel;
import burp.Highlighter.Highlighters;
import burp.Logs.LogEntry;
import burp.Logs.LogEntryMenu;
import burp.Logs.LogManager;
import burp.Logs.LogTableModel;
import burp.Redirect.Redirect;
import burp.Redirect.RedirectSettingsModel;
import burp.Replacements.Replacement;
import burp.Replacements.ReplacementTableModel;
import burp.Replacements.Replacements;
import burp.SSRF.SSRF;
import burp.SSRF.SSRFSettingsModel;
import burp.Sqli.Sqli;
import burp.Sqli.SqliSettingsModel;
import burp.Utils.DiffViewerPane;
import burp.Utils.HttpComparer;
import burp.Utils.Utils;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableModel;

public class AutoRepeater implements IMessageEditorController {

    // UI Component Dimensions
    public static final int TEXT_HEIGHT = new JTextField().getPreferredSize().height;
    public static final int BUTTON_HEIGHT = new JButton().getPreferredSize().height;

    public static final Dimension dialogDimension = new Dimension(450, TEXT_HEIGHT * 9);
    public static final Dimension comboBoxDimension = new Dimension(250, TEXT_HEIGHT);
    public static final Dimension textFieldDimension = new Dimension(250, TEXT_HEIGHT);
    public static final Dimension buttonDimension = new Dimension(80, TEXT_HEIGHT);
    public static final Dimension buttonPanelDimension = new Dimension(75, TEXT_HEIGHT * 9);
    public static final Dimension tableDimension = new Dimension(200, TEXT_HEIGHT * 9);
    public static final Dimension configurationPaneDimension = new Dimension(470, TEXT_HEIGHT * 9);

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private Gson gson;
    private JTabbedPane tabs;

    // Splitpane that holds top and bottom halves of the ui
    private JSplitPane mainSplitPane;

    // These hold the http request viewers at the bottom
    private JSplitPane originalRequestResponseSplitPane;
    private JSplitPane modifiedRequestResponseSplitPane;

    // this split pane holds the request list and configuration panes
    private JSplitPane userInterfaceSplitPane;


    private LogTable logTable;

    private DiffViewerPane requestComparer;
    private DiffViewerPane responseComparer;

    private DiffViewerPane requestLineComparer;
    private DiffViewerPane responseLineComparer;

    // request/response viewers
    private IMessageEditor originalRequestViewer;
    private IMessageEditor originalResponseViewer;
    private IMessageEditor modifiedRequestViewer;
    private IMessageEditor modifiedResponseViewer;

    // Panels for including request/response viewers + labels
    private JPanel originalRequestPanel;
    private JPanel modifiedRequestPanel;
    private JPanel originalResponsePanel;
    private JPanel modifiedResponsePanel;

    private JLabel originalRequestLabel;
    private JLabel modifiedRequestLabel;
    private JLabel originalResponseLabel;
    private JLabel modifiedResponseLabel;

    byte[] originalRequest;
    byte[] originalResponse;
    byte[] modifiedRequest;
    byte[] modifiedResponse;

    String requestDiff;
    String responseDiff;
    String requestLineDiff;
    String responseLineDiff;

    JScrollPane requestComparerScrollPane;
    JScrollPane responseComparerScollPane;

    JScrollPane requestLineComparerScrollPane;
    JScrollPane responseLineComparerScollPane;

    // List of log entries for LogTable
    private LogManager logManager;

    // The current item selected in the log table
    private IHttpRequestResponsePersisted currentOriginalRequestResponse;
    private IHttpRequestResponsePersisted currentModifiedRequestResponse;

    // 右边配置选项卡窗口
    private JPanel configurationPane;
    private JTabbedPane configurationTabbedPane;

    // The button that indicates weather AutoRepeater is active.
    private JToggleButton activatedButton;

    // Elements for configuration panel
    private Conditions conditions;
    private ConditionTableModel conditionsTableModel;


    // replace界面
//    private Replacements replacements;

    private Replacements ssrfReplacements;
    private Replacements redirectReplacements;
    private Replacements sqliReplacements;


    private ReplacementTableModel replacementsTableModel;
    private ReplacementTableModel ssrfReplacementsTableModel;
    private ReplacementTableModel redirectReplacementsTableModel;
    private ReplacementTableModel sqliReplacementsTableModel;

    private SSRF ssrfConfigReplacements;
    private Redirect redirectConfigReplacements;
    private Sqli sqliConfigReplacements;


    private Replacements baseReplacements;
    private ReplacementTableModel baseReplacementsTableModel;


    private Filters filters;
    private FilterTableModel filterTableModel;

    private Highlighters highlighters;
    private HighlighterUITableModel highlighterUITableModel;

    public AutoRepeater() {
        this.callbacks = BurpExtender.getCallbacks();
        helpers = callbacks.getHelpers();
        gson = BurpExtender.getGson();
        conditions = new Conditions();
        conditionsTableModel = conditions.getConditionTableModel();

//        replacements = new Replacements();
//        replacementsTableModel = replacements.getReplacementTableModel();

        ssrfReplacements = new Replacements();
        ssrfReplacementsTableModel = ssrfReplacements.getReplacementTableModel();

        redirectReplacements = new Replacements();
        redirectReplacementsTableModel = redirectReplacements.getReplacementTableModel();

        sqliReplacements = new Replacements();
        sqliReplacementsTableModel = sqliReplacements.getReplacementTableModel();


        baseReplacements = new Replacements();
        baseReplacementsTableModel = baseReplacements.getReplacementTableModel();

        ssrfConfigReplacements = new SSRF("null", "null", false);
        ssrfConfigReplacements.updateUIFromModel();

        redirectConfigReplacements = new Redirect("baidu.com", true);
        redirectConfigReplacements.updateUIFromModel();

        sqliConfigReplacements = new Sqli(true);
        sqliConfigReplacements.updateUIFromModel();

        logManager = new LogManager();

        logTable = new LogTable(logManager.getLogTableModel());
        filters = new Filters(logManager);

        filterTableModel = filters.getFilterTableModel();

        highlighters = new Highlighters(logManager, logTable);
        highlighterUITableModel = highlighters.getHighlighterUITableModel();


        List<String> ssrfDicts = Arrays.asList(
                "url", "link", "redirect", "redirect_url", "callback", "api",
                "endpoint", "api_url", "proxy", "proxy_url", "fetch", "download",
                "file", "data", "src", "source", "img", "image", "uri", "path",
                "load", "remote", "request", "fetch_url", "load_url", "get_url",
                "open_url", "read_url", "view_url", "content_url", "service_url",
                "webhook", "feed", "oembed_url", "metadata_url", "fileurl", "pingname", "ping", "exec"
        );

        // 初始化参数
        for (String dict : ssrfDicts) {
            ssrfReplacementsTableModel.addReplacement(new Replacement("Match Param Name, Replace Dnslog", dict, "null", "Replace First", "initialization", false));
        }

        List<String> redirectDicts = Arrays.asList(
                "url", "link", "redirect", "redirect_url", "callback", "return",
                "return_url", "return_to", "goto", "next", "location", "target",
                "jump", "jump_to", "success_url", "error_url", "continue",
                "continue_url", "continue_to", "continue_path", "continue_redirect",
                "continue_link", "destination", "dest", "site", "domain", "web",
                "to", "uri", "path", "load", "load_url"
        );

        for (String dict : redirectDicts) {
            redirectReplacementsTableModel.addReplacement(new Replacement("Match Param Name, Replace Redirect", dict, "null", "Replace First", "initialization", false));
        }

        List<String> sqliDicts = Arrays.asList(
                "id", "username", "password", "query", "search", "name",
                "input", "param", "value", "data", "url", "location",
                "order", "group", "sort", "limit", "page", "column", "field",
                "name", "user", "role"
        );
        for (String dict : sqliDicts) {
            sqliReplacementsTableModel.addReplacement(new Replacement("Match Param Name, Replace Sqli", dict, "null", "Replace First", "initialization", false));
        }



        createUI();
        setDefaultState();
        activatedButton.setSelected(true);
    }

    // 循环初始化配置文件，将参数初始化到各个组件中
    public AutoRepeater(JsonObject configurationJson) {
        this();
        // clear out the conditions from the default constructor
        conditionsTableModel.clear();
        filterTableModel.clear();
        // Initialize singular properties
        if (configurationJson.get("isActivated") != null) {
            activatedButton.setSelected(configurationJson.get("isActivated").getAsBoolean());
        }
        if (configurationJson.get("isWhitelistFilter") != null) {
            filters.setWhitelist(configurationJson.get("isWhitelistFilter").getAsBoolean());
        }

        // Initialize lists
        if (configurationJson.get("baseReplacements") != null) {
            for (JsonElement element : configurationJson.getAsJsonArray("baseReplacements")) {
                baseReplacementsTableModel.addReplacement(gson.fromJson(element, Replacement.class));
            }
        }

        if (configurationJson.get("ssrfReplacement") != null) {
            for (JsonElement element : configurationJson.getAsJsonArray("ssrfReplacement")) {
                ssrfReplacementsTableModel.addReplacement(gson.fromJson(element, Replacement.class));
            }
        }

        if (configurationJson.get("redirectReplacement") != null) {
            for (JsonElement element : configurationJson.getAsJsonArray("redirectReplacement")) {
                redirectReplacementsTableModel.addReplacement(gson.fromJson(element, Replacement.class));
            }
        }

        if (configurationJson.get("sqliReplacement") != null) {
            for (JsonElement element : configurationJson.getAsJsonArray("sqliReplacement")) {
                sqliReplacementsTableModel.addReplacement(gson.fromJson(element, Replacement.class));
            }
        }


        if (configurationJson.get("ssrfConfig") != null) {
            for (JsonElement element : configurationJson.getAsJsonArray("ssrfConfig")) {

                SSRFSettingsModel model = ssrfConfigReplacements.getSettingsModel();
                JsonObject elementObject = element.getAsJsonObject();

                model.setCeyeToken(elementObject.get("ceyeToken").getAsString());
                model.setCeyeDnsLog(elementObject.get("ceyeDnsLog").getAsString());
                model.setActivated(configurationJson.get("ssrfIsActivated").getAsBoolean());
                ssrfConfigReplacements.updateUIFromModel();

            }
        }

        if (configurationJson.get("redirectConfig") != null) {
            for (JsonElement element : configurationJson.getAsJsonArray("redirectConfig")) {

                RedirectSettingsModel model = redirectConfigReplacements.getSettingsModel();
                JsonObject elementObject = element.getAsJsonObject();

                model.setRedirectDomain(elementObject.get("redirectDomain").getAsString());
                model.setActivated(configurationJson.get("redirectIsActivated").getAsBoolean());

                redirectConfigReplacements.updateUIFromModel();
            }
        }

        if (configurationJson.get("sqliIsActivated") != null) {

            SqliSettingsModel model = sqliConfigReplacements.getSettingsModel();
            model.setActivated(configurationJson.get("sqliIsActivated").getAsBoolean());

            sqliConfigReplacements.updateUIFromModel();
        }

// 二次替换注释不用
//        if (configurationJson.get("replacements") != null) {
//            for (JsonElement element : configurationJson.getAsJsonArray("replacements")) {
//                replacementsTableModel.addReplacement(gson.fromJson(element, Replacement.class));
//            }
//        }
        if (configurationJson.get("conditions") != null) {
            for (JsonElement element : configurationJson.getAsJsonArray("conditions")) {
                conditionsTableModel.add(gson.fromJson(element, Condition.class));
            }
        }
        if (configurationJson.get("filters") != null) {
            for (JsonElement element : configurationJson.getAsJsonArray("filters")) {
                // 动态model更新table
                filterTableModel.add(gson.fromJson(element, Filter.class));
            }
        }
        if (configurationJson.get("highlighters") != null) {
            for (JsonElement element : configurationJson.getAsJsonArray("highlighters")) {
                HighlighterTableModel tempHighlighterTableModel = new HighlighterTableModel();
                JsonObject elementObject = element.getAsJsonObject();
                if (elementObject.get("color") != null) {
                    tempHighlighterTableModel.setColorName(elementObject.get("color").getAsString());
                }
                if (elementObject.get("comment") != null) {
                    if (!elementObject.get("comment").isJsonNull()) {
                        tempHighlighterTableModel.setComment(elementObject.get("comment").getAsString());
                    } else {
                        tempHighlighterTableModel.setComment("");
                    }
                }
                if (elementObject.get("enabled") != null) {
                    tempHighlighterTableModel.setEnabled(elementObject.get("enabled").getAsBoolean());
                }
                for (JsonElement highlighter : elementObject.get("highlighters").getAsJsonArray()) {
                    tempHighlighterTableModel.add(gson.fromJson(highlighter, Highlighter.class));
                }
                highlighterUITableModel.add(tempHighlighterTableModel);
            }
        }
        // If something was empty, put in the default values
        if (conditionsTableModel.getConditions().size() == 0) {
            setDefaultConditions();
        }
        if (filterTableModel.getFilters().size() == 0) {
            setDefaultFilters();
        }
    }

    public void setDefaultConditions() {
        conditionsTableModel.add(new Condition(
                "",
                "Sent From Tool",
                "Burp",
                ""
        ));

        conditionsTableModel.add(new Condition(
                "Or",
                "Request",
                "Contains Parameters",
                "",
                false
        ));

        conditionsTableModel.add(new Condition(
                "Or",
                "HTTP Method",
                "Does Not Match",
                "(GET|POST)",
                false
        ));

        conditionsTableModel.add(new Condition(
                "And",
                "URL",
                "Is In Scope",
                "",
                false
        ));
    }

    public void setDefaultFilters() {
        filterTableModel.add(new Filter(
                "",
                "Original",
                "Sent From Tool",
                "Burp",
                ""
        ));
    }

    private void setDefaultState() {
        setDefaultConditions();
        setDefaultFilters();
    }

    public JsonObject toJson() {
        JsonObject autoRepeaterJson = new JsonObject();

        SSRFSettingsModel ssrfModel = ssrfConfigReplacements.getSettingsModel();
        RedirectSettingsModel redirectModel = redirectConfigReplacements.getSettingsModel();
        SqliSettingsModel sqliModel = sqliConfigReplacements.getSettingsModel();

        JsonArray ssrfConfigArray = new JsonArray();
        JsonArray redirectConfigArray = new JsonArray();

        JsonObject ssrfConfigJsonObject = new JsonObject();
        ssrfConfigJsonObject.addProperty("ceyeToken", ssrfModel.getCeyeToken());
        ssrfConfigJsonObject.addProperty("ceyeDnsLog", ssrfModel.getCeyeDnsLog());
        ssrfConfigArray.add(ssrfConfigJsonObject);

        JsonObject redirectConfigJsonObject = new JsonObject();
        redirectConfigJsonObject.addProperty("redirectDomain", redirectModel.getRedirectDomain());
        redirectConfigArray.add(redirectConfigJsonObject);

        // Add Static Properties
        autoRepeaterJson.addProperty("isActivated", activatedButton.isSelected());
        autoRepeaterJson.addProperty("isWhitelistFilter", filters.isWhitelist());
        autoRepeaterJson.addProperty("ssrfIsActivated", ssrfModel.isActivated());
        autoRepeaterJson.addProperty("redirectIsActivated", redirectModel.isActivated());
        autoRepeaterJson.addProperty("sqliIsActivated", sqliModel.isActivated());

        // Add Arrays
        JsonArray baseReplacementsArray = new JsonArray();
        JsonArray ssrfReplacementsArray = new JsonArray();
        JsonArray redirectReplacementsArray = new JsonArray();
        JsonArray sqliReplacementsArray = new JsonArray();

//        JsonArray replacementsArray = new JsonArray();

        JsonArray conditionsArray = new JsonArray();
        JsonArray filtersArray = new JsonArray();
        JsonArray highlightersArray = new JsonArray();
        for (Condition c : conditionsTableModel.getConditions()) {
            conditionsArray.add(gson.toJsonTree(c));
        }

        for (Replacement r : baseReplacementsTableModel.getReplacements()) {
            baseReplacementsArray.add(gson.toJsonTree(r));
        }

        for (Replacement r : ssrfReplacementsTableModel.getReplacements()) {
            ssrfReplacementsArray.add(gson.toJsonTree(r));
        }

        for (Replacement r : redirectReplacementsTableModel.getReplacements()) {
            redirectReplacementsArray.add(gson.toJsonTree(r));
        }

        for (Replacement r : sqliReplacementsTableModel.getReplacements()) {
            sqliReplacementsArray.add(gson.toJsonTree(r));
        }

//        for (Replacement r : replacementsTableModel.getReplacements()) {
//            replacementsArray.add(gson.toJsonTree(r));
//        }
        for (Filter f : filterTableModel.getFilters()) {
            filtersArray.add(gson.toJsonTree(f));
        }
        for (HighlighterTableModel htm : highlighterUITableModel.getTableModels()) {
            JsonArray tempHighlightersArray = new JsonArray();
            for (Highlighter h : htm.getHighlighters()) {
                tempHighlightersArray.add(gson.toJsonTree(h));
            }
            JsonObject highlighterTableObject = new JsonObject();
            highlighterTableObject.addProperty("color", htm.getColorName());
            highlighterTableObject.addProperty("comment", htm.getComment());
            highlighterTableObject.addProperty("enabled", htm.isEnabled());
            highlighterTableObject.add("highlighters", tempHighlightersArray);
            highlightersArray.add(highlighterTableObject);
        }

        autoRepeaterJson.add("baseReplacements", baseReplacementsArray);

//        autoRepeaterJson.add("replacements", replacementsArray);

        autoRepeaterJson.add("conditions", conditionsArray);
        autoRepeaterJson.add("filters", filtersArray);
        autoRepeaterJson.add("highlighters", highlightersArray);
        autoRepeaterJson.add("ssrfConfig", ssrfConfigArray);
        autoRepeaterJson.add("redirectConfig", redirectConfigArray);
        autoRepeaterJson.add("ssrfReplacement", ssrfReplacementsArray);
        autoRepeaterJson.add("redirectReplacement", redirectReplacementsArray);
        autoRepeaterJson.add("sqliReplacement", sqliReplacementsArray);
        return autoRepeaterJson;
    }

    public JSplitPane getUI() {
        return mainSplitPane;
    }

    public LogTable getLogTable() {
        return logTable;
    }

    public LogManager getLogManager() {
        return logManager;
    }

    private void createUI() {
        GridBagConstraints c;
        Border grayline = BorderFactory.createLineBorder(Color.GRAY);
        // main splitpane
        mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        // splitpane that holds request and response viewers
        originalRequestResponseSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        modifiedRequestResponseSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

        // This tabbedpane includes the configuration panels
        configurationTabbedPane = new JTabbedPane();

        // Initialize Activated Button
        activatedButton = new JToggleButton("Activate AutoRepeater");
        activatedButton.addChangeListener(e -> {
            if (activatedButton.isSelected()) {
                activatedButton.setText("Deactivate AutoRepeater");
            } else {
                activatedButton.setText("Activate AutoRepeater");
            }
        });

        Dimension activatedDimension = new Dimension(200, TEXT_HEIGHT);
        activatedButton.setPreferredSize(activatedDimension);
        activatedButton.setMaximumSize(activatedDimension);
        activatedButton.setMinimumSize(activatedDimension);

        configurationPane = new JPanel();
        configurationPane.setLayout(new GridBagLayout());
        configurationPane.setMinimumSize(configurationPaneDimension);
        configurationPane.setPreferredSize(configurationPaneDimension);
        c = new GridBagConstraints();
        c.anchor = GridBagConstraints.NORTHWEST;
        configurationPane.add(activatedButton, c);
        c.fill = GridBagConstraints.BOTH;
        c.weightx = 1;
        c.weighty = 1;
        c.gridy = 1;

        configurationPane.add(configurationTabbedPane, c);

        JTabbedPane replacementsTabbedPane = new JTabbedPane();
        JTabbedPane logsTabbedPane = new JTabbedPane();
        JTabbedPane configTabbedPane = new JTabbedPane();


        replacementsTabbedPane.addTab("Base Replacements", baseReplacements.getUI());
//        replacementsTabbedPane.addTab("Replacements", replacements.getUI());
        replacementsTabbedPane.addTab("SSRF", ssrfReplacements.getUI());
        replacementsTabbedPane.addTab("Redirect", redirectReplacements.getUI());
        replacementsTabbedPane.addTab("Sqli", sqliReplacements.getUI());
        replacementsTabbedPane.addTab("Conditions", conditions.getUI());
        configTabbedPane.addTab("SSRF", ssrfConfigReplacements.getUI());
        configTabbedPane.addTab("Redirect", redirectConfigReplacements.getUI());
        configTabbedPane.addTab("Sqli", sqliConfigReplacements.getUI());
//        configTabbedPane.addTab("redirect", ssrfReplacements.getUI());
//        configTabbedPane.addTab("redirect", ssrfReplacements.getUI());

        logsTabbedPane.addTab("Log Filter", filters.getUI());
        logsTabbedPane.addTab("Log Highlighter", highlighters.getUI());

        configurationTabbedPane.add("Replacements", replacementsTabbedPane);
        configurationTabbedPane.add("Logs", logsTabbedPane);
        configurationTabbedPane.add("Config", configTabbedPane);

        // logtable 初始化渲染
        logTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(
                    JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                Component c =
                        super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                c.setBackground(
                        logManager.getLogTableModel().getLogEntry(
                                logTable.convertRowIndexToModel(row)).getBackgroundColor());
                if (isSelected) {
                    c.setBackground(
                            logManager.getLogTableModel().getLogEntry(
                                    logTable.convertRowIndexToModel(row)).getSelectedBackgroundColor());
                }
                return c;
            }
        });

        logTable.setAutoCreateRowSorter(true);

        logTable.getColumnModel().getColumn(0).setPreferredWidth(5);
        logTable.getColumnModel().getColumn(1).setPreferredWidth(30);
        logTable.getColumnModel().getColumn(2).setPreferredWidth(250);
        logTable.getColumnModel().getColumn(3).setPreferredWidth(20);
        logTable.getColumnModel().getColumn(4).setPreferredWidth(20);
        logTable.getColumnModel().getColumn(5).setPreferredWidth(40);
        logTable.getColumnModel().getColumn(6).setPreferredWidth(40);
        logTable.getColumnModel().getColumn(7).setPreferredWidth(30);
        logTable.getColumnModel().getColumn(8).setPreferredWidth(30);

        // 将logTable初始化到 JScrollPane 中，使每个单元格左对齐
        JScrollPane logTableScrollPane = new JScrollPane(logTable);
        logTableScrollPane.setMinimumSize(configurationPaneDimension);
        logTableScrollPane.setPreferredSize(new Dimension(10000, 10));

        // tabs with request/response viewers
        tabs = new JTabbedPane();

        tabs.addChangeListener(e -> {
            switch (tabs.getSelectedIndex()) {
                case 0:
                    updateOriginalRequestResponseViewer();
                    break;
                case 1:
                    updateModifiedRequestResponseViewer();
                    break;
                case 2:
                    updateDiffViewer();
                    break;
                default:
                    updateLineDiffViewer();
                    break;
            }
        });

        // Request / Response Viewers
        originalRequestViewer = callbacks.createMessageEditor(this, false);
        originalResponseViewer = callbacks.createMessageEditor(this, false);
        modifiedRequestViewer = callbacks.createMessageEditor(this, false);
        modifiedResponseViewer = callbacks.createMessageEditor(this, false);

        // Request / Response Labels
        originalRequestLabel = new JLabel("Request");
        originalResponseLabel = new JLabel("Response");
        modifiedRequestLabel = new JLabel("Request");
        modifiedResponseLabel = new JLabel("Response");

        JLabel diffRequestLabel = new JLabel("Request");
        JLabel diffResponseLabel = new JLabel("Response");

        JLabel lineDiffRequestLabel = new JLabel("Request");
        JLabel lineDiffResponseLabel = new JLabel("Response");

        originalRequestLabel.setForeground(Utils.getBurpOrange());
        originalResponseLabel.setForeground(Utils.getBurpOrange());
        modifiedRequestLabel.setForeground(Utils.getBurpOrange());
        modifiedResponseLabel.setForeground(Utils.getBurpOrange());
        diffRequestLabel.setForeground(Utils.getBurpOrange());
        diffResponseLabel.setForeground(Utils.getBurpOrange());
        lineDiffRequestLabel.setForeground(Utils.getBurpOrange());
        lineDiffResponseLabel.setForeground(Utils.getBurpOrange());

        originalRequestLabel.setFont(new Font("SansSerif", Font.BOLD, 14));
        originalResponseLabel.setFont(new Font("SansSerif", Font.BOLD, 14));
        modifiedRequestLabel.setFont(new Font("SansSerif", Font.BOLD, 14));
        modifiedResponseLabel.setFont(new Font("SansSerif", Font.BOLD, 14));
        diffRequestLabel.setFont(new Font("SansSerif", Font.BOLD, 14));
        diffResponseLabel.setFont(new Font("SansSerif", Font.BOLD, 14));
        lineDiffRequestLabel.setFont(new Font("SansSerif", Font.BOLD, 14));
        lineDiffResponseLabel.setFont(new Font("SansSerif", Font.BOLD, 14));

        // Initialize JPanels that hold request/response viewers and labels
        originalRequestPanel = new JPanel();
        modifiedRequestPanel = new JPanel();

        originalResponsePanel = new JPanel();
        modifiedResponsePanel = new JPanel();

        originalRequestPanel.setLayout(new BoxLayout(originalRequestPanel, BoxLayout.PAGE_AXIS));
        modifiedRequestPanel.setLayout(new BoxLayout(modifiedRequestPanel, BoxLayout.PAGE_AXIS));
        originalResponsePanel.setLayout(new BoxLayout(originalResponsePanel, BoxLayout.PAGE_AXIS));
        modifiedResponsePanel.setLayout(new BoxLayout(modifiedResponsePanel, BoxLayout.PAGE_AXIS));

        // Diff viewer stuff
        JSplitPane diffSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

        JPanel requestDiffPanel = new JPanel();
        JPanel responseDiffPanel = new JPanel();

        requestDiffPanel.setPreferredSize(new Dimension(100000, 100000));
        responseDiffPanel.setPreferredSize(new Dimension(100000, 100000));

        requestDiffPanel.setLayout(new GridBagLayout());
        responseDiffPanel.setLayout(new GridBagLayout());

        requestComparer = new DiffViewerPane();
        responseComparer = new DiffViewerPane();

        requestComparerScrollPane = new JScrollPane(requestComparer);
        responseComparerScollPane = new JScrollPane(responseComparer);

        c = new GridBagConstraints();
        c.anchor = GridBagConstraints.FIRST_LINE_START;
        requestDiffPanel.add(diffRequestLabel, c);
        c.gridy = 1;
        c.weightx = 1;
        c.weighty = 1;
        c.fill = GridBagConstraints.BOTH;
        requestDiffPanel.add(requestComparerScrollPane, c);

        c = new GridBagConstraints();
        c.anchor = GridBagConstraints.FIRST_LINE_START;
        responseDiffPanel.add(diffResponseLabel, c);
        c.gridy = 1;
        c.weightx = 1;
        c.weighty = 1;
        c.fill = GridBagConstraints.BOTH;
        responseDiffPanel.add(responseComparerScollPane, c);

        // Line Diff Viewer Stuff
        JSplitPane lineDiffSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

        // request
        JPanel requestLineDiffPanel = new JPanel();
        JPanel responseLineDiffPanel = new JPanel();

        requestLineDiffPanel.setPreferredSize(new Dimension(100000, 100000));
        responseLineDiffPanel.setPreferredSize(new Dimension(100000, 100000));

        requestLineDiffPanel.setLayout(new GridBagLayout());
        responseLineDiffPanel.setLayout(new GridBagLayout());

        requestLineComparer = new DiffViewerPane();
        responseLineComparer = new DiffViewerPane();

        requestLineComparerScrollPane = new JScrollPane(requestLineComparer);
        responseLineComparerScollPane = new JScrollPane(responseLineComparer);

        c = new GridBagConstraints();
        c.anchor = GridBagConstraints.FIRST_LINE_START;
        requestLineDiffPanel.add(lineDiffRequestLabel, c);
        c.gridy = 1;
        c.weightx = 1;
        c.weighty = 1;
        c.fill = GridBagConstraints.BOTH;
        requestLineDiffPanel.add(requestLineComparerScrollPane, c);

        c = new GridBagConstraints();
        c.anchor = GridBagConstraints.FIRST_LINE_START;
        responseLineDiffPanel.add(lineDiffResponseLabel, c);
        c.gridy = 1;
        c.weightx = 1;
        c.weighty = 1;
        c.fill = GridBagConstraints.BOTH;
        responseLineDiffPanel.add(responseLineComparerScollPane, c);

        // Add Viewers
        originalRequestPanel.add(originalRequestLabel);
        originalRequestPanel.add(originalRequestViewer.getComponent());
        originalRequestPanel.setPreferredSize(new Dimension(100000, 100000));

        originalResponsePanel.add(originalResponseLabel);
        originalResponsePanel.add(originalResponseViewer.getComponent());
        originalResponsePanel.setPreferredSize(new Dimension(100000, 100000));

        modifiedRequestPanel.add(modifiedRequestLabel);
        modifiedRequestPanel.add(modifiedRequestViewer.getComponent());
        modifiedRequestPanel.setPreferredSize(new Dimension(100000, 100000));

        modifiedResponsePanel.add(modifiedResponseLabel);
        modifiedResponsePanel.add(modifiedResponseViewer.getComponent());
        modifiedResponsePanel.setPreferredSize(new Dimension(100000, 100000));

        // Add viewers to the original splitpane
        originalRequestResponseSplitPane.setLeftComponent(originalRequestPanel);
        originalRequestResponseSplitPane.setRightComponent(originalResponsePanel);

        originalRequestResponseSplitPane.setResizeWeight(0.50);
        tabs.addTab("Original", originalRequestResponseSplitPane);

        // Add viewers to the modified splitpane
        modifiedRequestResponseSplitPane.setLeftComponent(modifiedRequestPanel);
        modifiedRequestResponseSplitPane.setRightComponent(modifiedResponsePanel);
        modifiedRequestResponseSplitPane.setResizeWeight(0.5);
        tabs.addTab("Modified", modifiedRequestResponseSplitPane);

        // Add diff tab
        diffSplitPane.setLeftComponent(requestDiffPanel);
        diffSplitPane.setRightComponent(responseDiffPanel);
        diffSplitPane.setResizeWeight(0.50);
        tabs.addTab("Diff", diffSplitPane);

        //Add line diff tab
        lineDiffSplitPane.setLeftComponent(requestLineDiffPanel);
        lineDiffSplitPane.setRightComponent(responseLineDiffPanel);
        lineDiffSplitPane.setResizeWeight(0.50);

        tabs.addTab("Line Diff", lineDiffSplitPane);

        mainSplitPane.setResizeWeight(.00000000000001);
        mainSplitPane.setBottomComponent(tabs);

        // 左右拆分视图格
        userInterfaceSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

        // 右边的config面板配置
        userInterfaceSplitPane.setRightComponent(configurationPane);

        // 左边log列表配置
        userInterfaceSplitPane.setLeftComponent(logTableScrollPane);
        userInterfaceSplitPane.setResizeWeight(1.0);
        mainSplitPane.setTopComponent(userInterfaceSplitPane);

        // Keep the split panes at the bottom the same size.
        originalRequestResponseSplitPane.addPropertyChangeListener(JSplitPane.DIVIDER_LOCATION_PROPERTY,
                pce -> {
                    modifiedRequestResponseSplitPane.setDividerLocation(
                            originalRequestResponseSplitPane.getDividerLocation());
                    diffSplitPane.setDividerLocation(
                            originalRequestResponseSplitPane.getDividerLocation());
                    lineDiffSplitPane.setDividerLocation(
                            originalRequestResponseSplitPane.getDividerLocation());
                }
        );
        modifiedRequestResponseSplitPane.addPropertyChangeListener(JSplitPane.DIVIDER_LOCATION_PROPERTY,
                pce -> {
                    originalRequestResponseSplitPane.setDividerLocation(
                            modifiedRequestResponseSplitPane.getDividerLocation());
                    diffSplitPane.setDividerLocation(
                            modifiedRequestResponseSplitPane.getDividerLocation());
                    lineDiffSplitPane.setDividerLocation(
                            modifiedRequestResponseSplitPane.getDividerLocation());
                }
        );
        diffSplitPane.addPropertyChangeListener(JSplitPane.DIVIDER_LOCATION_PROPERTY,
                pce -> {
                    originalRequestResponseSplitPane.setDividerLocation(
                            diffSplitPane.getDividerLocation());
                    modifiedRequestResponseSplitPane.setDividerLocation(
                            diffSplitPane.getDividerLocation());
                    lineDiffSplitPane.setDividerLocation(
                            diffSplitPane.getDividerLocation());
                }
        );
        lineDiffSplitPane.addPropertyChangeListener(JSplitPane.DIVIDER_LOCATION_PROPERTY,
                pce -> {
                    originalRequestResponseSplitPane.setDividerLocation(
                            lineDiffSplitPane.getDividerLocation());
                    modifiedRequestResponseSplitPane.setDividerLocation(
                            lineDiffSplitPane.getDividerLocation());
                    diffSplitPane.setDividerLocation(
                            lineDiffSplitPane.getDividerLocation());
                }
        );

        // I don't know what this actually does but I think it's correct
        callbacks.customizeUiComponent(mainSplitPane);
        callbacks.customizeUiComponent(logTable);
        callbacks.customizeUiComponent(logTableScrollPane);
        callbacks.customizeUiComponent(tabs);
    }

    // 修改发送request请求
    public void modifyAndSendRequestAndLog(
            int toolFlag,
            IHttpRequestResponse messageInfo) {

        // 基本替换功能
        if (activatedButton.isSelected() && toolFlag != BurpExtender.getCallbacks().TOOL_EXTENDER && baseReplacementsTableModel.getReplacements().size() != 0) {
            boolean meetsConditions = conditionsTableModel.check(toolFlag, messageInfo);
            if (meetsConditions) {
                // 创建一个集合以将每个新的唯一请求存储
                HashSet<IHttpRequestResponse> baseRequestSet = new HashSet<>();

                IHttpRequestResponse baseReplacedRequestResponse =
                        Utils.cloneIHttpRequestResponse(messageInfo);

                // 对捕获的请求执行所有基本替换
                for (Replacement globalReplacement : baseReplacementsTableModel.getReplacements()) {
                    baseReplacedRequestResponse.setRequest(
                            globalReplacement.performReplacement(baseReplacedRequestResponse, null));
                }
                baseRequestSet.add(baseReplacedRequestResponse);

//                // 将基本已替换请求添加到请求集中
//                if (replacementsTableModel.getReplacements().isEmpty()) {
//                    requestSet.add(baseReplacedRequestResponse);
//                }

//                // 对请求执行所有单独的替换+基本替换并将它们添加到集合中,二次替换
//                for (Replacement replacement : replacementsTableModel.getReplacements()) {
//                    IHttpRequestResponse newHttpRequest = Utils
//                            .cloneIHttpRequestResponse(baseReplacedRequestResponse);
//                    newHttpRequest.setRequest(replacement.performReplacement(newHttpRequest));
//                    requestSet.add(newHttpRequest);
//                }
                // 基本请求替换
                for (IHttpRequestResponse request : baseRequestSet) {
                    if (!Arrays.equals(request.getRequest(), messageInfo.getRequest())) {
                        //count += 1;
                        //BurpExtender.getCallbacks().printOutput("Sending Request " + count + " of " + requestSet.size());
                        IHttpRequestResponse modifiedRequestResponse =
                                callbacks.makeHttpRequest(messageInfo.getHttpService(), request.getRequest());
                        if (BurpExtender.getAutoRepeaterMenu().sendRequestsToPassiveScanner) {
                            BurpExtender.getCallbacks().doPassiveScan(
                                    modifiedRequestResponse.getHttpService().getHost(),
                                    modifiedRequestResponse.getHttpService().getPort(),
                                    modifiedRequestResponse.getHttpService().getProtocol().equals("https"),
                                    modifiedRequestResponse.getRequest(),
                                    modifiedRequestResponse.getResponse()
                            );
                        }
                        if (BurpExtender.getAutoRepeaterMenu().addRequestsToSiteMap) {
                            BurpExtender.getCallbacks().addToSiteMap(modifiedRequestResponse);
                        }
                        if (modifiedRequestResponse.getResponse() == null) {
                            modifiedRequestResponse.setResponse(new byte[0]);
                        }
                        LogEntry newLogEntry = new LogEntry(
                                logManager.getLogTableModel().getLogCount() + 1,
                                toolFlag,
                                callbacks.saveBuffersToTempFiles(messageInfo),
                                callbacks.saveBuffersToTempFiles(modifiedRequestResponse), "baseReplace");
                        highlighters.highlight(newLogEntry);
                        //int row = logManager.getRowCount();
                        logManager.addEntry(newLogEntry, filters);
                        // Highlight the rows
                        logManager.getLogTableModel().fireTableDataChanged();
                    }
                }

            }
        }


        // ssrf 漏洞判断
        if (ssrfConfigReplacements.getSettingsModel().isActivated() && toolFlag != BurpExtender.getCallbacks().TOOL_EXTENDER && ssrfReplacementsTableModel.getReplacements().size() != 0) {
            boolean meetsConditions = conditionsTableModel.check(toolFlag, messageInfo);
            if (meetsConditions) {
                // 创建一个集合以将每个新的唯一请求存储
                HashSet<IHttpRequestResponse> ssrfRequestSet = new HashSet<>();

                IHttpRequestResponse baseReplacedRequestResponse =
                        Utils.cloneIHttpRequestResponse(messageInfo);
                IExtensionHelpers helpers = BurpExtender.getHelpers();
                IRequestInfo analyzedRequest = helpers.analyzeRequest(baseReplacedRequestResponse);

                IHttpRequestResponse ssrfReplacedRequestResponse = Utils.cloneIHttpRequestResponse(messageInfo);
                // 对捕获的请求执行所有基本替换
                for (Replacement globalReplacement : ssrfReplacementsTableModel.getReplacements()) {
                    ssrfReplacedRequestResponse.setRequest(
                            globalReplacement.performReplacement(ssrfReplacedRequestResponse, ssrfConfigReplacements.getSettingsModel().getCeyeDnsLog()));
                }
                ssrfRequestSet.add(ssrfReplacedRequestResponse);

                // ssrf 漏洞判断
                for (IHttpRequestResponse request : ssrfRequestSet) {
                    if (!Arrays.equals(request.getRequest(), messageInfo.getRequest())) {

                        IHttpRequestResponse modifiedRequestResponse =
                                callbacks.makeHttpRequest(messageInfo.getHttpService(), request.getRequest());
                        if (BurpExtender.getAutoRepeaterMenu().sendRequestsToPassiveScanner) {
                            BurpExtender.getCallbacks().doPassiveScan(
                                    modifiedRequestResponse.getHttpService().getHost(),
                                    modifiedRequestResponse.getHttpService().getPort(),
                                    modifiedRequestResponse.getHttpService().getProtocol().equals("https"),
                                    modifiedRequestResponse.getRequest(),
                                    modifiedRequestResponse.getResponse()
                            );
                        }
                        if (BurpExtender.getAutoRepeaterMenu().addRequestsToSiteMap) {
                            BurpExtender.getCallbacks().addToSiteMap(modifiedRequestResponse);
                        }

                        if (modifiedRequestResponse.getResponse() == null) {
                            modifiedRequestResponse.setResponse(new byte[0]);
                        }


                        String url = "http://api.ceye.io/v1/records?token=" + ssrfConfigReplacements.getSettingsModel().getCeyeToken() + "&type=dns&filter=";
                        IHttpService httpService = callbacks.getHelpers().buildHttpService("api.ceye.io", 80, false);
                        IRequestInfo requestInfo = callbacks.getHelpers().analyzeRequest(httpService, callbacks.getHelpers().stringToBytes("GET " + url + " HTTP/1.1\r\nHost: api.ceye.io\r\n\r\n"));
                        IHttpRequestResponse response = callbacks.makeHttpRequest(httpService, callbacks.getHelpers().buildHttpMessage(requestInfo.getHeaders(), null));


                        // 获取响应字节数组并构建响应文本
                        byte[] responseBytes = response.getResponse();
                        String responseText = new String(responseBytes);

                        if (responseText.contains(analyzedRequest.getUrl().getHost())) {
                            LogEntry newLogEntry = new LogEntry(
                                    logManager.getLogTableModel().getLogCount() + 1,
                                    toolFlag,
                                    callbacks.saveBuffersToTempFiles(messageInfo),
                                    callbacks.saveBuffersToTempFiles(modifiedRequestResponse), "SSRF");
                            highlighters.highlight(newLogEntry);

                            //int row = logManager.getRowCount();
                            logManager.addEntry(newLogEntry, filters);

                            // 高亮显示行
                            logManager.getLogTableModel().fireTableDataChanged();
                        }

                    }
                }
            }

        }


        // 重定向漏洞判断
        if (redirectConfigReplacements.getSettingsModel().isActivated() && toolFlag != BurpExtender.getCallbacks().TOOL_EXTENDER && redirectReplacementsTableModel.getReplacements().size() != 0) {
            boolean meetsConditions = conditionsTableModel.check(toolFlag, messageInfo);
            if (meetsConditions) {
                IHttpRequestResponse redirectReplacedRequestResponse = Utils.cloneIHttpRequestResponse(messageInfo);
                HashSet<IHttpRequestResponse> redirectRequestSet = new HashSet<>();

                for (Replacement globalReplacement : redirectReplacementsTableModel.getReplacements()) {
                    redirectReplacedRequestResponse.setRequest(
                            globalReplacement.performReplacement(redirectReplacedRequestResponse, redirectConfigReplacements.getSettingsModel().getRedirectDomain()));
                }
                redirectRequestSet.add(redirectReplacedRequestResponse);

                for (IHttpRequestResponse redrequest : redirectRequestSet) {
                    if (!Arrays.equals(redrequest.getRequest(), messageInfo.getRequest())) {

                        IHttpRequestResponse modifiedRequestResponse =
                                callbacks.makeHttpRequest(messageInfo.getHttpService(), redrequest.getRequest());
                        if (BurpExtender.getAutoRepeaterMenu().sendRequestsToPassiveScanner) {
                            BurpExtender.getCallbacks().doPassiveScan(
                                    modifiedRequestResponse.getHttpService().getHost(),
                                    modifiedRequestResponse.getHttpService().getPort(),
                                    modifiedRequestResponse.getHttpService().getProtocol().equals("https"),
                                    modifiedRequestResponse.getRequest(),
                                    modifiedRequestResponse.getResponse()
                            );
                        }
                        if (BurpExtender.getAutoRepeaterMenu().addRequestsToSiteMap) {
                            BurpExtender.getCallbacks().addToSiteMap(modifiedRequestResponse);
                        }

                        if (modifiedRequestResponse.getResponse() == null) {
                            modifiedRequestResponse.setResponse(new byte[0]);
                        }


                        // 获取响应信息
                        byte[] responseBytes = modifiedRequestResponse.getResponse();
                        IResponseInfo responseInfo = callbacks.getHelpers().analyzeResponse(responseBytes);

                        // 获取响应状态码
                        int statusCode = responseInfo.getStatusCode();

                        if (statusCode == 302) {
                            LogEntry newLogEntry = new LogEntry(
                                    logManager.getLogTableModel().getLogCount() + 1,
                                    toolFlag,
                                    callbacks.saveBuffersToTempFiles(messageInfo),
                                    callbacks.saveBuffersToTempFiles(modifiedRequestResponse), "Redirect");
                            highlighters.highlight(newLogEntry);

                            //int row = logManager.getRowCount();
                            logManager.addEntry(newLogEntry, filters);

                            // 高亮显示行
                            logManager.getLogTableModel().fireTableDataChanged();
                        }

                    }
                }

            }
        }

        // 注入判断
        if (sqliConfigReplacements.getSettingsModel().isActivated() && toolFlag != BurpExtender.getCallbacks().TOOL_EXTENDER && sqliReplacementsTableModel.getReplacements().size() != 0) {
            boolean meetsConditions = conditionsTableModel.check(toolFlag, messageInfo);
            if (meetsConditions) {
                // 创建一个集合以将每个新的唯一请求存储
                HashSet<IHttpRequestResponse> sqliRequestSet = new HashSet<>();

                IHttpRequestResponse sqliReplacedRequestResponse = Utils.cloneIHttpRequestResponse(messageInfo);
                if (sqliConfigReplacements.getSettingsModel().isActivated()) {
                    for (Replacement globalReplacement : sqliReplacementsTableModel.getReplacements()) {
                        sqliReplacedRequestResponse.setRequest(
                                globalReplacement.performReplacement(sqliReplacedRequestResponse, "'"));
                    }
                    sqliRequestSet.add(sqliReplacedRequestResponse);
                }

                for (IHttpRequestResponse sqlirequest : sqliRequestSet) {
                    if (!Arrays.equals(sqlirequest.getRequest(), messageInfo.getRequest())) {

                        IHttpRequestResponse modifiedRequestResponse =
                                callbacks.makeHttpRequest(messageInfo.getHttpService(), sqlirequest.getRequest());
                        if (BurpExtender.getAutoRepeaterMenu().sendRequestsToPassiveScanner) {
                            BurpExtender.getCallbacks().doPassiveScan(
                                    modifiedRequestResponse.getHttpService().getHost(),
                                    modifiedRequestResponse.getHttpService().getPort(),
                                    modifiedRequestResponse.getHttpService().getProtocol().equals("https"),
                                    modifiedRequestResponse.getRequest(),
                                    modifiedRequestResponse.getResponse()
                            );
                        }
                        if (BurpExtender.getAutoRepeaterMenu().addRequestsToSiteMap) {
                            BurpExtender.getCallbacks().addToSiteMap(modifiedRequestResponse);
                        }

                        if (modifiedRequestResponse.getResponse() == null) {
                            modifiedRequestResponse.setResponse(new byte[0]);
                        }


                        // 获取响应信息
                        byte[] responseBytes = modifiedRequestResponse.getResponse();
                        IResponseInfo responseInfo = callbacks.getHelpers().analyzeResponse(responseBytes);
                        byte[] responseBodyBytes = Arrays.copyOfRange(responseBytes, responseInfo.getBodyOffset(), responseBytes.length);
                        String responseBodyText = helpers.bytesToString(responseBodyBytes);
                        String regex = "(?i)(error|sql|syntax|query|database)";

                        Pattern pattern = Pattern.compile(regex);
                        Matcher matcher = pattern.matcher(responseBodyText);

                        if (matcher.find()) {
                            LogEntry newLogEntry = new LogEntry(
                                    logManager.getLogTableModel().getLogCount() + 1,
                                    toolFlag,
                                    callbacks.saveBuffersToTempFiles(messageInfo),
                                    callbacks.saveBuffersToTempFiles(modifiedRequestResponse), "Sqli");
                            highlighters.highlight(newLogEntry);

                            //int row = logManager.getRowCount();
                            logManager.addEntry(newLogEntry, filters);

                            // 高亮显示行
                            logManager.getLogTableModel().fireTableDataChanged();
                        }

                    }
                }


            }
        }

    }


    public LogTableModel getLogTableModel() {
        return logManager.getLogTableModel();
    }

    public void toggleConfigurationPane(boolean visible) {
        if (visible) {
            userInterfaceSplitPane.setRightComponent(configurationPane);
        } else {
            userInterfaceSplitPane.remove(configurationPane);
        }
    }

    // Implement IMessageEditorController
    @Override
    public byte[] getRequest() {
        switch (tabs.getSelectedIndex()) {
            case 0:
                return currentOriginalRequestResponse.getRequest();
            case 1:
                return currentModifiedRequestResponse.getRequest();
            default:
                return new byte[0];
        }
    }

    @Override
    public byte[] getResponse() {
        switch (tabs.getSelectedIndex()) {
            case 0:
                return currentOriginalRequestResponse.getResponse();
            case 1:
                return currentModifiedRequestResponse.getResponse();
            default:
                return new byte[0];
        }
    }

    @Override
    public IHttpService getHttpService() {
        switch (tabs.getSelectedIndex()) {
            case 0:
                return currentOriginalRequestResponse.getHttpService();
            case 1:
                return currentModifiedRequestResponse.getHttpService();
            default:
                return null;
        }
    }

    private void updateOriginalRequestResponseViewer() {
        SwingUtilities.invokeLater(() -> {
            // Set Original Request Viewer
            if (originalRequest != null) {
                originalRequestViewer.setMessage(originalRequest, true);
            } else {
                originalRequestViewer.setMessage(new byte[0], true);
            }

            // Set Original Response Viewer
            if (originalResponse != null) {
                originalResponseViewer.setMessage(originalResponse, false);
            } else {
                originalResponseViewer.setMessage(new byte[0], false);
            }
        });
    }

    private void updateModifiedRequestResponseViewer() {
        SwingUtilities.invokeLater(() -> {
            // Set Modified Request Viewer
            if (modifiedRequest != null) {
                modifiedRequestViewer.setMessage(modifiedRequest, true);
            } else {
                modifiedRequestViewer.setMessage(new byte[0], true);
            }

            // Set Modified Response Viewer
            if (modifiedResponse != null) {
                modifiedResponseViewer.setMessage(modifiedResponse, false);
            } else {
                modifiedResponseViewer.setMessage(new byte[0], false);
            }
        });
    }

    private void updateDiffViewer() {
        SwingUtilities.invokeLater(() -> {
            if (originalRequest != null && modifiedRequest != null) {
                requestComparer.setText(requestDiff);
                requestComparer.setCaretPosition(0);
            } else {
                requestComparer.setText("");
            }

            // Set Response Diff Viewer
            if (originalResponse != null && modifiedResponse != null) {
                responseComparer.setText(responseDiff);
                responseComparer.setCaretPosition(0);
            } else {
                responseComparer.setText("");
            }
        });
    }

    private void updateLineDiffViewer() {
        SwingUtilities.invokeLater(() -> {
            if (originalRequest != null && modifiedRequest != null) {
                requestLineComparer.setText(requestLineDiff);
                requestLineComparer.setCaretPosition(0);
            } else {
                requestLineComparer.setText("");
            }

            // Set Response Diff Viewer
            if (originalResponse != null && modifiedResponse != null) {
                responseLineComparer.setText(responseLineDiff);
                responseLineComparer.setCaretPosition(0);
            } else {
                responseLineComparer.setText("");
            }
        });
    }

    private void updateRequestViewers() {
        switch (tabs.getSelectedIndex()) {
            case 0:
                updateOriginalRequestResponseViewer();
                break;
            case 1:
                updateModifiedRequestResponseViewer();
                break;
            case 2:
                updateDiffViewer();
                break;
            default:
                updateLineDiffViewer();
                break;
        }
    }

    // JTable for Viewing Logs
    public class LogTable extends JTable {

        public LogTable(TableModel tableModel) {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            super.changeSelection(row, col, toggle, extend);
            // show the log entry for the selected row
            LogEntry logEntry = logManager.getLogEntry(convertRowIndexToModel(row));

            //final LogTable _this = this;
            this.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    onMouseEvent(e);
                }

                @Override
                public void mouseReleased(MouseEvent e) {
                    onMouseEvent(e);
                }

                @Override
                public void mousePressed(MouseEvent e) {
                    onMouseEvent(e);
                }

                // Event for clearing the logs
                private void onMouseEvent(MouseEvent e) {
                    if (SwingUtilities.isRightMouseButton(e)) {
                        Point p = e.getPoint();
                        final int row = convertRowIndexToModel(rowAtPoint(p));
                        final int col = convertColumnIndexToModel(columnAtPoint(p));
                        if (e.isPopupTrigger() && e.getComponent() instanceof JTable) {
                            getSelectionModel().setSelectionInterval(row, row);
                            new LogEntryMenu(logManager, logTable, row, col)
                                    .show(e.getComponent(), e.getX(), e.getY());
                        }
                    }
                }
            });

            // There's a delay while changing selections because setting the diff viewer is slow.
            new Thread(() -> {
                originalRequest = logEntry.getOriginalRequestResponse().getRequest();
                originalResponse = logEntry.getOriginalRequestResponse().getResponse();
                modifiedRequest = logEntry.getModifiedRequestResponse().getRequest();
                modifiedResponse = logEntry.getModifiedRequestResponse().getResponse();
                currentOriginalRequestResponse = logEntry.getOriginalRequestResponse();
                currentModifiedRequestResponse = logEntry.getModifiedRequestResponse();

                SwingUtilities.invokeLater(() -> {
                    requestDiff = HttpComparer
                            .diffText(new String(originalRequest), new String(modifiedRequest));
                    updateRequestViewers();
                });
                SwingUtilities.invokeLater(() -> {
                    responseDiff = HttpComparer
                            .diffText(new String(originalResponse), new String(modifiedResponse));
                    updateRequestViewers();
                });
                SwingUtilities.invokeLater(() -> {
                    requestLineDiff = HttpComparer
                            .diffLines(new String(originalRequest), new String(modifiedRequest));
                    updateRequestViewers();

                });
                SwingUtilities.invokeLater(() -> {
                    responseLineDiff = HttpComparer
                            .diffLines(new String(originalResponse), new String(modifiedResponse));
                    updateRequestViewers();
                });

                //new Thread(() -> {
                //  requestDiff = HttpComparer
                //      .diffText(new String(originalRequest), new String(modifiedRequest));
                //  updateRequestViewers();
                //}).start();
                //new Thread(() -> {
                //  responseDiff = HttpComparer
                //      .diffText(new String(originalResponse), new String(modifiedResponse));
                //  updateRequestViewers();
                //}).start();
                //new Thread(() -> {
                //  requestLineDiff = HttpComparer
                //      .diffLines(new String(originalRequest), new String(modifiedRequest));
                //  updateRequestViewers();
                //}).start();
                //new Thread(() -> {
                //  responseLineDiff = HttpComparer
                //      .diffLines(new String(originalResponse), new String(modifiedResponse));
                //  updateRequestViewers();
                //}).start();
                //updateRequestViewers();
                // Hack to speed up the ui
            }).start();
        }
    }
}