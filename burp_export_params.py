from burp import IBurpExtender, IContextMenuFactory
from javax.swing import JMenuItem
from java.awt import Toolkit
from java.awt.datatransfer import StringSelection
import json
import re
from java.util import ArrayList


class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("Parameter Names Exporter")
        callbacks.registerContextMenuFactory(self)

    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        menu_list.add(JMenuItem("Export Parameter Names",
                                actionPerformed=lambda x: self.export_parameters()))
        return menu_list

    def export_parameters(self):

        proxy_history = self._callbacks.getProxyHistory()
        parameter_names = set()

        for history_item in proxy_history:
            request_info = self._helpers.analyzeRequest(history_item)

            if not self._callbacks.isInScope(request_info.getUrl()):
                continue

            request_bytes = history_item.getRequest()
            request_string = self._helpers.bytesToString(request_bytes)

            params = request_info.getParameters()
            for param in params:
                parameter_names.add(param.getName())

            # JSON parameters in body
            if "Content-Type: application/json" in request_string:
                body_offset = request_info.getBodyOffset()
                body = request_string[body_offset:]
                try:
                    json_data = json.loads(body)
                    self.extract_json_keys(json_data, parameter_names)
                except:
                    pass

            # XML parameters in body
            if "Content-Type: application/xml" in request_string or "Content-Type: text/xml" in request_string:
                body_offset = request_info.getBodyOffset()
                body = request_string[body_offset:]
                xml_params = re.findall(r'<(\w+)[>\s]', body)
                parameter_names.update(xml_params)

        result = "\n".join(sorted(parameter_names))

        string_selection = StringSelection(result)
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(string_selection, None)

        print("Exported Parameters:")
        print(result)
        print("\nParameters copied to clipboard!")

    def extract_json_keys(self, obj, param_set):
        """Recursively extract keys from JSON objects"""
        if isinstance(obj, dict):
            for key, value in obj.items():
                param_set.add(key)
                self.extract_json_keys(value, param_set)
        elif isinstance(obj, list):
            for item in obj:
                self.extract_json_keys(item, param_set)