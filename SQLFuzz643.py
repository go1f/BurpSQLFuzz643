from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from array import array


class BurpExtender(IBurpExtender, IScannerCheck):

    #
    # implement IBurpExtender
    #

    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("SQLFuzz643")

        # register ourselves as a custom scanner check
        callbacks.registerScannerCheck(self)


    def _update_parameter(self, request, name, payload):
        para = self._helpers.buildParameter(name, payload, 0)
        
        if ( self._helpers.getRequestParameter(request, name) is None):
            request = self._helpers.addParameter(request, para)
        else:
            request = self._helpers.updateParameter(request, para)

        return request

    # helper method to search a response for occurrences of a literal match string
    # and return a list of start/end offsets
    def _charge_reponse(self, response, match):
        matches = []
        reslen = len(response)

        for _match in match:
            start = 0
            matchlen = len(_match)
            while start < reslen:
                start = self._helpers.indexOf(response, _match, True, start, reslen)
                if start == -1:
                    break
                matches.append(array('i', [start, start + matchlen]))
                start += matchlen

        return matches


    #
    # implement IScannerCheck
    #

    def doPassiveScan(self, baseRequestResponse):
        print("Start Passive Scan.")
        
        params = ["ord","sort","order"]
        payloads = ["extractvalue(1,concat(0x7e,92643))", "1,updatexml(1,concat(0x7e,92643),1)+ASC", "%E9%8E%88%27%22%5C%28"]
        issues = []

        GREP_Certain_STRINGS = ["~92643"]
        GREP_Certain_STRINGS_BYTES = [bytearray(GREP_STRING) for GREP_STRING in GREP_Certain_STRINGS]
        GREP_Tentative_STRINGS = ["SQL syntax"]
        GREP_Tentative_STRINGS_BYTES = [bytearray(GREP_STRING) for GREP_STRING in GREP_Tentative_STRINGS]


        for param in params:
            for payload in payloads:
                req = self._update_parameter(baseRequestResponse.getRequest(), param, payload)
                
                _params = []
                for _p in self._helpers.analyzeRequest(req).getParameters():
                    _params.append(_p.getName())
                _params_str = ",".join(_params)
                _url = self._helpers.analyzeRequest(baseRequestResponse.getHttpService(),req).getUrl()
                print("Scan: " + str(_url) + ". Params contain " + _params_str)


                checkRequestResponse = self._callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), req)


                # look for matches of our passive check grep string
                matches1 = self._charge_reponse(checkRequestResponse.getResponse(), GREP_Certain_STRINGS_BYTES)
                matches2 = self._charge_reponse(checkRequestResponse.getResponse(), GREP_Tentative_STRINGS_BYTES)
                if (len(matches1) == 0 and len(matches2) == 0):
                    continue

                confidence = "Certain" if matches1 else "Tentative"
                detail = "The vuln param is " + str(param) + ". Params contain " + _params_str
                name = "SQL Error Vuln Param: " + str(param)

                issues.append(CustomScanIssue(
                    checkRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(checkRequestResponse).getUrl(),
                    [self._callbacks.applyMarkers(checkRequestResponse, None, matches1 if confidence=="Certain" else matches2)],
                    name,
                    detail,
                    "High",
                    confidence))
                print("*Issue: " + issues[-1].getIssueName() + ". " + issues[-1].getIssueDetail())

                # if found issues, no more payload checking. Reference to consolidateDuplicateIssues method logic.
                break
            
        # report the issue
        return issues

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        pass

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        # This method is called when multiple issues are reported for the same URL 
        # path by the same extension-provided check. The value we return from this 
        # method determines how/whether Burp consolidates the multiple issues
        # to prevent duplication
        #
        # Since the issue name is sufficient to identify our issues as different,
        # if both issues have the same name, only report the existing issue
        # otherwise report both issues
        
        # print("check-1: " + existingIssue.getIssueDetail())
        # print("check-2: " + newIssue.getIssueDetail())
        if existingIssue.getIssueName() == newIssue.getIssueName() and \
         existingIssue.getUrl() == newIssue.getUrl() and \
         existingIssue.getIssueDetail() == newIssue.getIssueDetail():
            return -1

        return 0

#
# class implementing IScanIssue to hold our custom scan issue details
#
class CustomScanIssue (IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity, confidence):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0x00100200

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
