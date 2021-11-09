import json
import csv
# import ipwhois
import codecs

"""
ToDo:
1) think on other methods - parse mail forwarding rule event
2) write documentation for the sake of documentation
3) export methods to make life easier for usage
4) never ever think of GUI
"""

O365_CSV_USERNAME = 1
O365_CSV_JSONDATA = 3
O365_DICT_USER = 0
O365_DICT_JSON = 1

class Office365:
    o365_log = {}
    o365_user_ips = {}
    o365_succ_client_ips = {}
    o365_fail_client_ips = {}
    o365_succ_client_auth = {}
    o365_user_succ_ip_intersection = {}
    o365_fail_succ_ip_intersection = {}
    o365_user_mail_items_access = {}
    o365_user_mail_items_deleted = []

    def __init__(self, audit_log_file):
        with codecs.open(audit_log_file, 'r', "utf-8") as temp_o365:
            o365_csv_log = csv.reader(temp_o365, delimiter=',')
            next(o365_csv_log, None)  # skip csv headers
            for auditLogEntry in o365_csv_log:  # read data from csv to dict
                if not auditLogEntry[O365_CSV_USERNAME] in self.o365_log:
                    self.o365_log.update({auditLogEntry[O365_CSV_USERNAME]: ()})
                self.o365_log.update(
                    {auditLogEntry[O365_CSV_USERNAME]:
                                self.o365_log[auditLogEntry[O365_CSV_USERNAME]] + (auditLogEntry[O365_CSV_JSONDATA],)})

        self.getSuccessfulLogonClientIPs()
        self.getLogonIpsAndUserAgent()
        self.getFailedLogonClientIPs()

    def getSuccessfulLogonClientIPs(self):
        for o365_username, o365_user_events in self.o365_log.items():
            client_ips = set()
            for event in o365_user_events:
                tmp = json.loads(event)
                if tmp["Operation"] == "UserLoggedIn":
                    client_ips.add(tmp["ClientIP"])
            self.o365_succ_client_ips.update({o365_username: client_ips})

    def getFailedLogonClientIPs(self):
        for o365_username, o365_user_events in self.o365_log.items():
            client_ips = set()
            for event in o365_user_events:
                tmp = json.loads(event)
                if tmp["Operation"] == "UserLoginFailed":
                    client_ips.add(tmp["ClientIP"])
            self.o365_fail_client_ips.update({o365_username: client_ips})


    def getIntersectionsWithMaliciousIPs(self, maliciousIPSet):
        for user, user_ip_set in self.o365_succ_client_ips.items():
            self.o365_user_succ_ip_intersection.update({user: user_ip_set.intersection(maliciousIPSet)})
        for user, user_ip_set in self.o365_fail_client_ips.items():
            self.o365_fail_succ_ip_intersection.update({user: user_ip_set.intersection(maliciousIPSet)})

    def getLogonIpsAndUserAgent(self):
        for o365_username, o365_user_events in self.o365_log.items():
            client_auth_data = set()
            for event in o365_user_events:
                tmp = json.loads(event)
                if tmp["Operation"] == "UserLoggedIn":
                    for extended_properties in tmp["ExtendedProperties"]:
                        if extended_properties["Name"] == "UserAgent":
                            client_auth_data.add((tmp["CreationTime"], tmp["ClientIP"], extended_properties["Value"]))
            self.o365_succ_client_auth.update({o365_username: client_auth_data})


    def getMailItemsAccessEvents(self):
        for o365_username, o365_user_events in self.o365_log.items():
            client_ips = []
            for event in o365_user_events:
                tmp = json.loads(event)
                if tmp["Operation"] == "MailItemsAccessed":
                    client_ips.append((tmp["ClientIP"], tmp["CreationTime"], tmp["Item"]))
                self.o365_user_mail_items_access.update({o365_username: client_ips})

    def getHardDeleteEvents(self):
        for o365_username, o365_user_events in self.o365_log.items():
            for event in o365_user_events:
                tmp = json.loads(event)
                if tmp["Operation"] == "SoftDelete":
                    continue
                for i in tmp["AffectedItems"]:
                    try:
                        self.o365_user_mail_items_deleted.append((tmp["CreationTime"], i["InternetMessageId"], i["Subject"]))
                    except KeyError as e:
                        continue

    def getDataFromLog(self, eventType, logEntryFields):
        parseResult = {}
        for o365_username, o365_user_events in self.o365_log.items():
            tmpList = []
            for event in o365_user_events:
                tmp = json.loads(event)
                if tmp["Operation"] == eventType:
                    tmpListInt = []
                    for i in range(0, len(logEntryFields)):
                        tmpListInt.append(tmp[logEntryFields[i]])             # fill every element of tuple with value
                    tmpList.append(tuple(tmpListInt))
                parseResult.update({o365_username: tmpList})
        return parseResult

