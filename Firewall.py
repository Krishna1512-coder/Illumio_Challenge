import ipaddress
import csv

class Helper:
    
    #to check if given val(ip/port) is range oror not
    def isRange(self, val):
        if "-" in val:
            return True
        else:
            return False

    #converting ip address to int
    def ipToInt(self, ipaddr):
        return int(ipaddress.IPv4Address(ipaddr))
    
    #get tuple of ipaddresses from given ip address/range
    def getIpTuple(self, ip):
        if self.isRange(ip):
            iprange = ip.split("-")
            return (self.ipToInt(iprange[0]), self.ipToInt(iprange[1]))
        else:
            return (self.ipToInt(ip), self.ipToInt(ip))
    
    #to merge overlapping ip address ranges
    def merge_ip_intervals(self, intervals):
        intervals.sort(key = lambda x: x[0])
        merged = []
        for interval in intervals:
                if not merged or merged[-1][1] < interval[0]:
                    merged.append(interval)
                else:
                    merged[-1] = (merged[0], max(merged[-1][1], interval[1]))
        return merged


class Firewall:
    
    def __init__(self, pathtofile):
        helper = Helper()
        self.firewall_rules = {}
        with open(pathtofile, 'r') as f:
            reader = csv.reader(f)
            for rule in reader:
                direction_rule = rule[0]
                protocol_rule = rule[1]
                port_rule = rule[2]
                ip_rule = rule[3]
                
                if direction_rule not in self.firewall_rules:
                    self.firewall_rules[direction_rule] = {}
                if protocol_rule not in self.firewall_rules[direction_rule]:
                    self.firewall_rules[direction_rule][protocol_rule] = {}
                
                ipTuple = helper.getIpTuple(ip_rule)
                
                
                if helper.isRange(port_rule):
                    port_range = port_rule.split("-")
                    for port in range(int(port_range[0]), int(port_range[1]) + 1):
                        if port in self.firewall_rules[direction_rule][protocol_rule]:
                            self.firewall_rules[direction_rule][protocol_rule][port].append(ipTuple)
                        else:
                            self.firewall_rules[direction_rule][protocol_rule][port] = [ipTuple]
                else:
                    if int(port_rule) in self.firewall_rules[direction_rule][protocol_rule]:
                        self.firewall_rules[direction_rule][protocol_rule][int(port_rule)].append(ipTuple)
                    else:
                        self.firewall_rules[direction_rule][protocol_rule][int(port_rule)] = [ipTuple]
            
            for direction in self.firewall_rules.keys():
                for protocol in self.firewall_rules[direction].keys():
                    for port, iprange_list in self.firewall_rules[direction][protocol].items():
                        self.firewall_rules[direction][protocol][port] = helper.merge_ip_intervals(iprange_list)
    
    def check_ip_present(self, iprangelist, ipaddr):
        left, right = 0, len(iprangelist) - 1
        while left <= right:
            pivot = left + (right - left) // 2

            if iprangelist[pivot][0] <= ipaddr and iprangelist[pivot][1] >= ipaddr:
                return True

            if ipaddr < iprangelist[pivot][0]:
                right = pivot - 1
            else:
                left = pivot + 1
        return False
    
    def accept_packet(self, direction, protocol, port, ipaddr):
        helper = Helper()
        if direction not in self.firewall_rules:
            return False
        if protocol not in self.firewall_rules[direction]:
            return False
        if port not in self.firewall_rules[direction][protocol]:
            return False
        
        ipaddr = helper.ipToInt(ipaddr)
        return self.check_ip_present(self.firewall_rules[direction][protocol][port], ipaddr)
