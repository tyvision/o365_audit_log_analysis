from o365 import Office365

"""
:brief This methods get WHOIS data about IPv4 addresses listed in a dictionary
:param dict_ips - variable dict type with IPv4 list
:param ip_whois_file - path to the file with IPv4 list and whois data about them
:param failed_lookup_ip_file - path to the file with IPv4 list that failed to lookup
"""

def get_whois_data(ip_addr):
    print("getting info about ipv4 address {}".format(ip_addr))
    ip_addr = ip_addr.strip('\n').split(':')[0]                 # cut the port value
    ip_info = ipwhois.IPWhois(ip_addr.strip('\n'))
    obj = ''
    try:
        obj = ip_info.lookup_whois()
    except ipwhois.exceptions.ASNRegistryError as e:
        print("unsuccessful.. try again later")
        return -1
    return obj


def o365_resolv_clients_ip(o365_log_file, o365_client):
    res = csv.writer(open(o365_client + "_resolv.csv", 'w'))
    failed = []
    for entry in o365_log_file[o365_client]:
        obj = get_whois_data(entry)
        if obj == -1:
            failed.append(entry)
        else:
            res.writerow((entry.strip('\n'), obj['asn_cidr'], obj['nets'][0]['address']))
    for i in failed:
        obj = get_whois_data(i)
        if obj != -1:
            res.writerow((i.strip('\n'), obj['asn_cidr'], obj['nets'][0]['address']))


def main():
    tmp = Office365("AuditLog_2021-07-31_2021-10-26.csv")
    # print(tmp.getDataFromLog("UserLoggedIn", ["CreationTime", "ClientIP"]))
    # print (tmp.o365_succ_client_auth)
    for user in tmp.o365_succ_client_auth:
        print ("DATA FOR USER {0}".format(user))
        print("DATE      |       IP       |    User Agent   ")
        for i in tmp.o365_succ_client_auth[user]:
            print ("{0}  |   {1}   |   {2}".format(i[0], i[1], i[2]))


if __name__ == '__main__':
    main()
