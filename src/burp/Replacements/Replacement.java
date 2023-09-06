package burp.Replacements;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;
import burp.Utils.Utils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.ListIterator;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;


public class Replacement {
    public static final String[] REPLACEMENT_TYPE_OPTIONS = {

            "Request String",
            "Request Header",
            "Request Body",
            "Request Param Name",
            "Request Param Value",
            "Request Cookie Name",
            "Request Cookie Value",
            "Request First Line",

            "Add Header",

            "Remove Parameter By Name",
            "Remove Parameter By Value",
            "Remove Cookie By Name",
            "Remove Cookie By Value",
            "Remove Header By Name",
            "Remove Header By Value",

            "Match Param Name, Replace Value",
            "Match Param Name, Replace Dnslog",
            "Match Param Name, Replace Redirect",
            "Match Param Name, Replace Sqli",
            "Match Cookie Name, Replace Value",
            "Match Header Name, Replace Value",
//            "Match Param Name, Replace Dnslog",
//            "Match Json Key, Replace Value",
            //"Remove Header By Name",
            //"Remove Header By Value"
    };

    public static final String[] REPLACEMENT_COUNT_OPTINONS = {
            "Replace First",
            "Replace All"
    };

    private enum MatchAndReplaceType {
        MATCH_NAME_REPLACE_NAME,
        MATCH_NAME_REPLACE_VALUE,
        MATCH_VALUE_REPLACE_VALUE,
        MATCH_VALUE_REPLACE_NAME,
        MATCH_NAME_REMOVE,
        MATCH_VALUE_REMOVE,
        MATCH_NAME_REPLACE_DNSLOG,
        MATCH_NAME_REPLACE_REDIRECT,
        MATCH_NAME_REPLACE_SQLI,
        MATCH_NAME_REPLACE_JSON,

    }

    private String type;
    private String match;
    private String replace;
    private String comment;
    private String which;

    private Boolean isRegexMatch;
    private Boolean isEnabled;

    public Replacement(
            String type,
            String match,
            String replace,
            String which,
            String comment,
            boolean isRegexMatch) {
        this.type = type;
        this.match = match;
        this.replace = replace;
        this.which = which;
        this.comment = comment;
        this.isRegexMatch = isRegexMatch;
        this.isEnabled = true;
    }

    public Replacement(
            String type,
            String match,
            String replace,
            String which,
            String comment,
            boolean isRegexMatch,
            boolean isEnabled) {
        this(type, match, replace, which, comment, isRegexMatch);
        this.setEnabled(isEnabled);
    }

    public Replacement(Replacement replacement) {
        this(replacement.getType(),
                replacement.getMatch(),
                replacement.getReplace(),
                replacement.getWhich(),
                replacement.getComment(),
                replacement.isRegexMatch(),
                replacement.isEnabled());
    }

    private byte[] updateBurpParam(
            byte[] request,
            int parameterType,
            MatchAndReplaceType matchAndReplaceType, String flag) {
        IExtensionHelpers helpers = BurpExtender.getHelpers();
        IRequestInfo analyzedRequest = helpers.analyzeRequest(request);
        // Need to only use params that can be added or removed.


        List<IParameter> parameters = analyzedRequest.getParameters().stream()
                .filter(p -> p.getType() == parameterType)
                .collect(Collectors.toList());
        List<IParameter> originalParameters = analyzedRequest.getParameters().stream()
                .filter(p -> p.getType() == parameterType)
                .collect(Collectors.toList());

        boolean wasChanged = false;
        for (ListIterator<IParameter> iterator = parameters.listIterator(); iterator.hasNext(); ) {
            int i = iterator.nextIndex();
            IParameter currentParameter = iterator.next();
            //BurpExtender.getCallbacks().printOutput(currentParameter.getName());
            //BurpExtender.getCallbacks().printOutput(currentParameter.getValue());
            if (currentParameter.getType() == parameterType) {
                switch (matchAndReplaceType) {
                    case MATCH_NAME_REPLACE_NAME:
                        // 每个if语句都检查是否为isRegexMatch&&check regex
                        // || 常规字符串比较
                        if ((this.isRegexMatch && currentParameter.getName().matches(this.match))
                                || currentParameter.getName().equals(this.match)) {
                            parameters.set(i, helpers.buildParameter(
                                    this.replace,
                                    currentParameter.getValue(),
                                    currentParameter.getType()));
                            wasChanged = true;
                        }
                        break;
                    case MATCH_NAME_REPLACE_VALUE:
                        if ((this.isRegexMatch && currentParameter.getName().matches(this.match))
                                || currentParameter.getName().equals(this.match)) {
                            parameters.set(i, helpers.buildParameter(
                                    currentParameter.getName(),
                                    this.replace,
                                    currentParameter.getType()));
                            wasChanged = true;
                        }
                        break;
                    case MATCH_VALUE_REPLACE_VALUE:
                        if ((this.isRegexMatch && currentParameter.getValue().matches(this.match))
                                || currentParameter.getValue().equals(this.match)) {
                            parameters.set(i, helpers.buildParameter(
                                    currentParameter.getName(),
                                    this.replace,
                                    currentParameter.getType()));
                            wasChanged = true;
                        }
                        break;
                    case MATCH_VALUE_REPLACE_NAME:
                        if ((this.isRegexMatch && currentParameter.getValue().matches(this.match))
                                || currentParameter.getValue().equals(this.match)) {
                            parameters.set(i, helpers.buildParameter(
                                    currentParameter.getName(),
                                    this.replace,
                                    currentParameter.getType()));
                            wasChanged = true;
                        }
                        break;
                    case MATCH_NAME_REMOVE:
                        if ((this.isRegexMatch && currentParameter.getName().matches(this.match))
                                || currentParameter.getName().equals(this.match)) {
                            iterator.remove();
                            wasChanged = true;
                        }
                        break;
                    case MATCH_VALUE_REMOVE:
                        if ((this.isRegexMatch && currentParameter.getValue().matches(this.match))
                                || currentParameter.getValue().equals(this.match)) {
                            iterator.remove();
                            wasChanged = true;
                        }
                    case MATCH_NAME_REPLACE_DNSLOG:
                        if ((this.isRegexMatch && currentParameter.getName().matches(this.match))
                                || currentParameter.getName().equals(this.match)) {

                            String host = analyzedRequest.getHeaders().get(1);
                            String subhost = extractIPorDomain(host);

                            String replace = "http://"+subhost + "." + flag;

                            parameters.set(i, helpers.buildParameter(
                                    currentParameter.getName(),
                                    replace,
                                    currentParameter.getType()));
                            wasChanged = true;
                        }
                        break;
                    case MATCH_NAME_REPLACE_REDIRECT:
                        if ((this.isRegexMatch && currentParameter.getName().matches(this.match))
                                || currentParameter.getName().equals(this.match)) {
                            String replace = flag;
                            parameters.set(i, helpers.buildParameter(
                                    currentParameter.getName(),
                                    replace,
                                    currentParameter.getType()));
                            wasChanged = true;
                        }
                        break;
                    case MATCH_NAME_REPLACE_SQLI:
                        if ((this.isRegexMatch && currentParameter.getName().matches(this.match))
                                || currentParameter.getName().equals(this.match)) {
                            String replace = parameters.get(i).getValue() + flag;
                            parameters.set(i, helpers.buildParameter(
                                    currentParameter.getName(),
                                    replace,
                                    currentParameter.getType()));
                            wasChanged = true;
                        }
                        break;
                    default:
                        break;
                }
            }
            // Bail if anything was changed
            if (this.which.equals("Replace First")) {
                if (wasChanged) {
                    break;
                }
            }
        }
        if (wasChanged) {
            byte[] tempRequest = Arrays.copyOf(request, request.length);

            // Remove every parameter
            for (IParameter param : originalParameters) {
                tempRequest = helpers.removeParameter(tempRequest, param);
            }
            // Add them back
            for (IParameter param : parameters) {
                tempRequest = helpers.addParameter(tempRequest, param);
            }

            // Update the body and headers
            IRequestInfo tempAnalyzedRequest = helpers.analyzeRequest(tempRequest);
            byte[] body = Arrays
                    .copyOfRange(tempRequest, tempAnalyzedRequest.getBodyOffset(), tempRequest.length);
            List<String> headers = tempAnalyzedRequest.getHeaders();

            // 将值初始化，防止显示以上个value的再替换
            for (int i = 0; i < originalParameters.size(); i++) {
                parameters.set(i, originalParameters.get(i));
            }

            return helpers.buildHttpMessage(headers, body);
        }
        // Return the modified request
        return request;
    }

    public static String extractIPorDomain(String input) {
        String regexIP = "Host: (\\d+\\.\\d+\\.\\d+\\.\\d+)";
        String regexDomain = "Host: ([^\\s]+)";

        Pattern patternIP = Pattern.compile(regexIP);
        Matcher matcherIP = patternIP.matcher(input);

        Pattern patternDomain = Pattern.compile(regexDomain);
        Matcher matcherDomain = patternDomain.matcher(input);

        if (matcherIP.find()) {
            return matcherIP.group(1);
        } else if (matcherDomain.find()) {
            return matcherDomain.group(1);
        } else {
            return input;
        }
    }

    // This is a hack around binary content causing requests to send
    private byte[] updateContent(byte[] request) {
        if (replaceFirst()) {
            return Utils.byteArrayRegexReplaceFirst(request, this.match, this.replace);
        } else {
            return Utils.byteArrayRegexReplaceAll(request, this.match, this.replace);
        }
    }

    private boolean replaceFirst() {
        return this.which.equals("Replace First");
    }

    private byte[] updateHeader(byte[] request) {
        IExtensionHelpers helpers = BurpExtender.getHelpers();
        IRequestInfo analyzedRequest = helpers.analyzeRequest(request);
        List<String> headers = analyzedRequest.getHeaders();
        byte[] body = Arrays.copyOfRange(request, analyzedRequest.getBodyOffset(), request.length);
        ArrayList<String> newHeaders = new ArrayList<>();
        boolean wasChanged = false;
        for (String header : headers) {
            if (!replaceFirst() || (replaceFirst() && !wasChanged)) {
                if (this.isRegexMatch) {
                    if (header.matches(this.match)) {
                        header = this.replace;
                        wasChanged = true;
                    }
                } else {
                    if (header.equals(this.match)) {
                        header = this.replace;
                        wasChanged = true;
                    }
                }
            }
            // Don't add empty headers, they mess things up
            if (!header.equals("")) {
                newHeaders.add(header);
            }
        }
        return helpers.buildHttpMessage(newHeaders, body);
    }

    private byte[] addHeader(byte[] request) {
        IExtensionHelpers helpers = BurpExtender.getHelpers();
        IRequestInfo analyzedRequest = helpers.analyzeRequest(request);
        List<String> headers = analyzedRequest.getHeaders();
        // Strip content-length to make sure it's the last param
        if (headers.get(headers.size() - 1).startsWith("Content-Length:")) {
            headers.remove(headers.size() - 1);
        }
        byte[] body = Arrays.copyOfRange(request, analyzedRequest.getBodyOffset(), request.length);
        headers.add(this.replace);
        return helpers.buildHttpMessage(headers, body);
    }

    private byte[] matchHeaderNameUpdateValue(byte[] request) {
        IExtensionHelpers helpers = BurpExtender.getHelpers();
        IRequestInfo analyzedRequest = helpers.analyzeRequest(request);
        List<String> headers = analyzedRequest.getHeaders();
        byte[] body = Arrays.copyOfRange(request, analyzedRequest.getBodyOffset(), request.length);
        ArrayList<String> newHeaders = new ArrayList<>();
        boolean wasChanged = false;
        for (String header : headers) {
            String[] splitHeader = header.split(":", 2);
            if (splitHeader.length == 2) {
                String headerName = splitHeader[0];
                if (!replaceFirst() || (replaceFirst() && !wasChanged)) {
                    if (this.isRegexMatch) {
                        if (headerName.matches(this.match)) {
                            header = headerName + ": " + this.replace;
                            wasChanged = true;
                        }
                    } else {
                        if (headerName.equals(this.match)) {
                            header = headerName + ": " + this.replace;
                            wasChanged = true;
                        }
                    }
                }
            }
            // Don't add empty headers, they mess things up
            if (!header.equals("")) {
                newHeaders.add(header);
            }
        }
        return helpers.buildHttpMessage(newHeaders, body);
    }

    // 匹配key
    private void modifyJson(JSONObject jsonObject, String keyToMatch, String newValue, boolean modifyAll) throws JSONException {
        for (String key : jsonObject.keySet()) {
            Object value = jsonObject.get(key);
            if (value instanceof JSONObject) {
                modifyJson((JSONObject) value, keyToMatch, newValue, modifyAll); // Recursive call for nested objects
            } else if (key.equals(keyToMatch)) {
                jsonObject.put(key, newValue);
                if (!modifyAll) {
                    break; // Stop processing after first match if modifyAll is false
                }
            }
        }
    }

    private static void modifyJsonReg(JSONObject jsonObject, Pattern keyPattern, String newValue, boolean modifyAll) throws JSONException {
        for (String key : jsonObject.keySet()) {
            Object value = jsonObject.get(key);
            if (value instanceof JSONObject) {
                modifyJsonReg((JSONObject) value, keyPattern, newValue, modifyAll); // Recursive call for nested objects
            } else {
                Matcher matcher = keyPattern.matcher(key);
                if (matcher.find()) {
                    jsonObject.put(key, newValue);
                    if (!modifyAll) {
                        break; // Stop processing after first match if modifyAll is false
                    }
                }
            }
        }
    }

    private static boolean doesKeyExist(JSONObject jsonObject, String k) {
        Pattern keyPattern = Pattern.compile(k, Pattern.CASE_INSENSITIVE);
        for (String key : jsonObject.keySet()) {
            Object value = jsonObject.get(key);
            Matcher matcher = keyPattern.matcher(key);
            boolean isMatch = matcher.find(); // Check if the key matches the pattern
            if (isMatch) {
                return true;
            }
            if (value instanceof JSONObject) {
                if (doesKeyExist((JSONObject) value, k)) {
                    return true;
                }
            }
        }

        return false;
    }

    // byte[] request = messageInfo.getRequest();
    private byte[] matchJsonKeyUpdateValue(byte[] request, MatchAndReplaceType matchAndReplaceType, String flag) {
        IExtensionHelpers helpers = BurpExtender.getHelpers();
        IRequestInfo analyzedRequest = helpers.analyzeRequest(request);

        String replace = this.replace;

        switch (matchAndReplaceType) {
            case MATCH_NAME_REPLACE_DNSLOG:
                String host = analyzedRequest.getHeaders().get(1);
                String subhost = extractIPorDomain(host);
                replace = "http://"+subhost + "." + flag;
                break;
            case MATCH_NAME_REPLACE_REDIRECT:
                replace = flag;
                break;
            case MATCH_NAME_REPLACE_SQLI:
                replace = flag;
                break;

        }

        String requestBody = new String(request);

        // Extract JSON data from the body
        int bodyOffset = analyzedRequest.getBodyOffset();
        String jsonData = requestBody.substring(bodyOffset);

        Pattern keyPattern = Pattern.compile(this.match, Pattern.CASE_INSENSITIVE);

        try {
            JSONObject jsonObject = new JSONObject(jsonData);

            boolean key = doesKeyExist(jsonObject, this.match);
            if (key == false) {
                return request;
            }
            if (this.isRegexMatch) {
                modifyJsonReg(jsonObject, keyPattern, replace, !replaceFirst());
            } else {
                modifyJson(jsonObject, this.match, replace, !replaceFirst());
            }

            // Serialize the modified JSON back to a string
            String modifiedJsonData = jsonObject.toString();
            return helpers.buildHttpMessage(analyzedRequest.getHeaders(), modifiedJsonData.getBytes());

        } catch (Exception e) {
            BurpExtender.getCallbacks().printError("Error parsing or modifying JSON: " + e.getMessage());
        }

        return request;
    }

    private byte[] updateRequestBody(byte[] request) {
        IExtensionHelpers helpers = BurpExtender.getHelpers();
        IRequestInfo analyzedRequest = helpers.analyzeRequest(request);
        List<String> headers = analyzedRequest.getHeaders();
        byte[] body = Arrays.copyOfRange(request, analyzedRequest.getBodyOffset(), request.length);
        boolean wasChanged = false;
        String bodyString;

        try {
            bodyString = new String(body, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            return request;
        }

        if (this.isRegexMatch) {
            if (bodyString.matches(this.match)) {
                body = this.replace.getBytes();
                wasChanged = true;
            }
        } else {
            if (bodyString.equals(this.match)) {
                body = bodyString.replace(this.match, this.replace).getBytes();
                wasChanged = true;
            }
        }
        // This helps deal with binary data getting messed up from the string conversion and causing a new request.
        if (wasChanged) {
            return helpers.buildHttpMessage(headers, body);
        } else {
            return request;
        }
    }

    private byte[] updateRequestParamName(byte[] request,String flag) {
        if (!Utils.isRequestMultipartForm(request)) {
            request = updateBurpParam(request, IParameter.PARAM_BODY,
                    MatchAndReplaceType.MATCH_NAME_REPLACE_NAME,flag);
            return updateBurpParam(request, IParameter.PARAM_URL,
                    MatchAndReplaceType.MATCH_NAME_REPLACE_NAME,flag);
        } else {
            return request;
        }
    }

    private byte[] updateRequestParamValue(byte[] request,String flag) {
        if (!Utils.isRequestMultipartForm(request)) {
            request = updateBurpParam(request, IParameter.PARAM_BODY,
                    MatchAndReplaceType.MATCH_VALUE_REPLACE_VALUE,flag);
            return updateBurpParam(request, IParameter.PARAM_URL,
                    MatchAndReplaceType.MATCH_VALUE_REPLACE_VALUE,flag);
        } else {
            return request;
        }
    }

    private byte[] updateRequestParamValueByName(byte[] request,String flag) {
        if (Utils.isRequestMultipartJson(request)) {
            request = matchJsonKeyUpdateValue(request, MatchAndReplaceType.MATCH_NAME_REPLACE_JSON,flag);
            return request;
        } else if (!Utils.isRequestMultipartForm(request)) {
            request = updateBurpParam(request, IParameter.PARAM_BODY,
                    MatchAndReplaceType.MATCH_NAME_REPLACE_VALUE,flag);
            return updateBurpParam(request, IParameter.PARAM_URL,
                    MatchAndReplaceType.MATCH_NAME_REPLACE_VALUE,flag);
        } else {
            return request;
        }
    }

    private byte[] updateRequestParamDnslogByName(byte[] request, String flag) {
        if (Utils.isRequestMultipartJson(request)) {
            request = matchJsonKeyUpdateValue(request, MatchAndReplaceType.MATCH_NAME_REPLACE_DNSLOG, flag);
            return request;
        } else if (!Utils.isRequestMultipartForm(request)) {
            request = updateBurpParam(request, IParameter.PARAM_BODY,
                    MatchAndReplaceType.MATCH_NAME_REPLACE_DNSLOG, flag);
            return updateBurpParam(request, IParameter.PARAM_URL,
                    MatchAndReplaceType.MATCH_NAME_REPLACE_DNSLOG, flag);
        } else {
            return request;
        }
    }

    private byte[] updateRequestParamRedirectByName(byte[] request, String flag) {
        if (Utils.isRequestMultipartJson(request)) {
            request = matchJsonKeyUpdateValue(request, MatchAndReplaceType.MATCH_NAME_REPLACE_REDIRECT, flag);
            return request;
        } else if (!Utils.isRequestMultipartForm(request)) {
            request = updateBurpParam(request, IParameter.PARAM_BODY,
                    MatchAndReplaceType.MATCH_NAME_REPLACE_REDIRECT, flag);
            return updateBurpParam(request, IParameter.PARAM_URL,
                    MatchAndReplaceType.MATCH_NAME_REPLACE_REDIRECT, flag);
        } else {
            return request;
        }
    }

    private byte[] updateRequestParamSqliByName(byte[] request, String flag) {
        if (Utils.isRequestMultipartJson(request)) {
            request = matchJsonKeyUpdateValue(request, MatchAndReplaceType.MATCH_NAME_REPLACE_SQLI, flag);
            return request;
        } else if (!Utils.isRequestMultipartForm(request)) {
            request = updateBurpParam(request, IParameter.PARAM_BODY,
                    MatchAndReplaceType.MATCH_NAME_REPLACE_SQLI, flag);
            return updateBurpParam(request, IParameter.PARAM_URL,
                    MatchAndReplaceType.MATCH_NAME_REPLACE_SQLI, flag);
        } else {
            return request;
        }
    }

    private byte[] updateCookieName(byte[] request,String flag) {
        return updateBurpParam(request, IParameter.PARAM_COOKIE,
                MatchAndReplaceType.MATCH_NAME_REPLACE_NAME,flag);
    }

    private byte[] updateCookieValue(byte[] request,String flag) {
        return updateBurpParam(request, IParameter.PARAM_COOKIE,
                MatchAndReplaceType.MATCH_VALUE_REPLACE_VALUE,flag);
    }

    private byte[] removeParameterByName(byte[] request,String flag) {
        if (!Utils.isRequestMultipartForm(request)) {
            request = updateBurpParam(request, IParameter.PARAM_BODY,
                    MatchAndReplaceType.MATCH_NAME_REMOVE,flag);
            return updateBurpParam(request, IParameter.PARAM_URL,
                    MatchAndReplaceType.MATCH_NAME_REMOVE,flag);
        } else {
            return request;
        }
    }

    private byte[] removeParameterByValue(byte[] request,String flag) {
        if (Utils.isRequestMultipartForm(request)) {
            request = updateBurpParam(request, IParameter.PARAM_BODY,
                    MatchAndReplaceType.MATCH_VALUE_REMOVE,flag);
            return updateBurpParam(request, IParameter.PARAM_URL,
                    MatchAndReplaceType.MATCH_VALUE_REMOVE,flag);
        } else {
            return request;
        }
    }

    private byte[] removeCookieByName(byte[] request,String flag) {
        return updateBurpParam(request, IParameter.PARAM_COOKIE,
                MatchAndReplaceType.MATCH_NAME_REMOVE,flag);
    }

    private byte[] removeCookieByValue(byte[] request,String flag) {
        return updateBurpParam(request, IParameter.PARAM_COOKIE,
                MatchAndReplaceType.MATCH_VALUE_REMOVE,flag);
    }

    private byte[] removeHeaderByName(byte[] request) {
        IExtensionHelpers helpers = BurpExtender.getHelpers();
        IRequestInfo analyzedRequest = helpers.analyzeRequest(request);
        byte[] body = Arrays.copyOfRange(request, analyzedRequest.getBodyOffset(), request.length);
        List<String> headers;
        if (replaceFirst()) {
            AtomicInteger index = new AtomicInteger(0);
            if (isRegexMatch()) {
                headers = analyzedRequest.getHeaders().stream()
                        .filter((x -> !(x.split(":")[0].matches(getMatch()) && index.getAndIncrement() < 1)))
                        .collect(Collectors.toCollection(ArrayList::new));
            } else {
                headers = analyzedRequest.getHeaders().stream()
                        .filter(x -> !(x.split(":")[0].equals(getMatch()) && index.getAndIncrement() < 1))
                        .collect(Collectors.toCollection(ArrayList::new));
            }
        } else {
            if (isRegexMatch()) {
                headers = analyzedRequest.getHeaders().stream()
                        .filter(x -> !(x.split(":")[0].matches(getMatch())))
                        .collect(Collectors.toCollection(ArrayList::new));
            } else {
                headers = analyzedRequest.getHeaders().stream()
                        .filter(x -> !(x.split(":")[0].equals(getMatch())))
                        .collect(Collectors.toCollection(ArrayList::new));
            }
        }
        return helpers.buildHttpMessage(headers, body);
    }

    private byte[] removeHeaderByValue(byte[] request) {
        IExtensionHelpers helpers = BurpExtender.getHelpers();
        IRequestInfo analyzedRequest = helpers.analyzeRequest(request);
        byte[] body = Arrays.copyOfRange(request, analyzedRequest.getBodyOffset(), request.length);
        List<String> headers;
        if (replaceFirst()) {
            AtomicInteger index = new AtomicInteger(0);
            if (isRegexMatch()) {
                headers = analyzedRequest.getHeaders().stream()
                        .filter(x -> x.split(":")[1].matches(getMatch()) && index.getAndIncrement() < 1)
                        .collect(Collectors.toCollection(ArrayList::new));
            } else {
                headers = analyzedRequest.getHeaders().stream()
                        .filter(x -> x.split(":")[1].equals(getMatch()) && index.getAndIncrement() < 1)
                        .collect(Collectors.toCollection(ArrayList::new));
            }
        } else {
            if (isRegexMatch()) {
                headers = analyzedRequest.getHeaders().stream()
                        .filter(x -> x.split(":")[1].matches(getMatch()))
                        .collect(Collectors.toCollection(ArrayList::new));
            } else {
                headers = analyzedRequest.getHeaders().stream()
                        .filter(x -> x.split(":")[1].equals(getMatch()))
                        .collect(Collectors.toCollection(ArrayList::new));
            }
        }
        return helpers.buildHttpMessage(headers, body);
    }

    private byte[] updateCookieValueByName(byte[] request,String flag) {
        return updateBurpParam(request, IParameter.PARAM_COOKIE,
                MatchAndReplaceType.MATCH_NAME_REPLACE_VALUE,flag);
    }

    private byte[] updateRequestFirstLine(byte[] request) {
        IExtensionHelpers helpers = BurpExtender.getHelpers();
        IRequestInfo analyzedRequest = helpers.analyzeRequest(request);
        List<String> headers = analyzedRequest.getHeaders();
        byte[] body = Arrays.copyOfRange(request, analyzedRequest.getBodyOffset(), request.length);
        String firstRequestString = headers.get(0);
        if (replaceFirst()) {
            headers.set(0, firstRequestString.replaceFirst(this.match, this.replace));
        } else {
            headers.set(0, firstRequestString.replaceAll(this.match, this.replace));
        }
        return helpers.buildHttpMessage(headers, body);
    }

    // TODO: Modify this to return List<Byte[]> to support "Replace Each"
    public byte[] performReplacement(IHttpRequestResponse messageInfo, String flag) {
        byte[] request = messageInfo.getRequest();
        if (this.isEnabled) {
            switch (this.type) {
                case ("Request Header"):
                    return updateHeader(request);
                case ("Request Body"):
                    return updateRequestBody(request);
                case ("Request Param Name"):
                    return updateRequestParamName(request,flag);
                case ("Request Param Value"):
                    return updateRequestParamValue(request,flag);
                case ("Request Cookie Name"):
                    return updateCookieName(request,flag);
                case ("Request Cookie Value"):
                    return updateCookieValue(request,flag);
                case ("Request First Line"):
                    return updateRequestFirstLine(request);
                case ("Request String"):
                    return updateContent(request);
                case ("Add Header"):
                    return addHeader(request);
                case ("Remove Parameter By Name"):
                    return removeParameterByName(request,flag);
                case ("Remove Parameter By Value"):
                    return removeParameterByValue(request,flag);
                case ("Remove Cookie By Name"):
                    return removeCookieByName(request,flag);
                case ("Remove Cookie By Value"):
                    return removeCookieByValue(request,flag);
                case ("Remove Header By Name"):
                    return removeHeaderByName(request);
                case ("Remove Header By Value"):
                    return removeHeaderByValue(request);
                case ("Match Param Name, Replace Value"):
                    return updateRequestParamValueByName(request,flag);
                case ("Match Cookie Name, Replace Value"):
                    return updateCookieValueByName(request,flag);
                case ("Match Header Name, Replace Value"):
                    return matchHeaderNameUpdateValue(request);
                case ("Match Param Name, Replace Dnslog"):
                    return updateRequestParamDnslogByName(request, flag);
                case ("Match Param Name, Replace Redirect"):
                    return updateRequestParamRedirectByName(request, flag);
                case ("Match Param Name, Replace Sqli"):
                    return updateRequestParamSqliByName(request, flag);

                //  case ("Match Json Key, Replace Value"):
//                    return matchJsonKeyUpdateValue(request);
                default:
                    return request;
            }
        }
        return request;
    }

    public String getType() {
        return type;
    }

    public String getMatch() {
        return match;
    }

    public String getReplace() {
        return replace;
    }

    public String getComment() {
        return comment;
    }

    public boolean isRegexMatch() {
        return isRegexMatch;
    }

    public boolean isEnabled() {
        return isEnabled;
    }

    public void setType(String type) {
        this.type = type;
    }

    public void setMatch(String match) {
        this.match = match;
    }

    public void setReplace(String replace) {
        this.replace = replace;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    public void setRegexMatch(Boolean regexMatch) {
        isRegexMatch = regexMatch;
    }

    public void setEnabled(Boolean enabled) {
        isEnabled = enabled;
    }

    public String getWhich() {
        return which;
    }

    public void setWhich(String which) {
        this.which = which;
    }

    public Boolean getRegexMatch() {
        return isRegexMatch;
    }

    public Boolean getEnabled() {
        return isEnabled;
    }
}
