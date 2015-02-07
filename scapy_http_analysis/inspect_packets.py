__author__ = 'dujodwal'
from scapy.all import *
from scapy.error import Scapy_Exception
from mimetools import Message
from StringIO import StringIO
import json

class InvalidPcapFile(Exception):pass

class ParsePackets(object):

    TCP_filter = lambda x,pkt: "TCP" in pkt
    UDP_filter = lambda x,pkt: "UDP" in pkt
    HTTP_request = lambda x,pkt: "TCP" in pkt and pkt.haslayer("Raw") and (pkt.dport == 80 or pkt.dport == 443)
    HTTP_redirects = lambda x,pkt: "TCP" in pkt and pkt.haslayer("Raw") and (pkt.sport == 80 or pkt.sport == 443)
    HTTP_payloadSize = lambda x,pkt: "TCP" in pkt and pkt.haslayer("Raw") and (pkt.sport == 80 or pkt.sport == 443)
    TCP_SYN = lambda x,pkt: "TCP" in pkt and not pkt.haslayer("Raw") and (pkt.dport == 80 or pkt.dport == 443)

    def __init__(self,pcap_location):
        if isinstance(pcap_location,str):
            try:
                self.capture = rdpcap(pcap_location)
            except IOError:
                raise InvalidPcapFile("File location: %s not found"%pcap_location)
            except Scapy_Exception:
                raise InvalidPcapFile("Not a good pcap file!")
        else:
            raise InvalidPcapFile("Please provide a string value for the location")

    def applyFilters(self,capture,filter_func):
        try:
            filtered_data = capture.filter(filter_func)
        except Scapy_Exception:
            raise Scapy_Exception("Failed to filter the pcap file")
        if filtered_data is None:
            print("Nothing matched in the filter")
        return filtered_data

    def count_TCP_Packets(self):
        TCP_packets = self.applyFilters(self.capture,self.TCP_filter)
        return (len(TCP_packets))

    def count_UDP_Packets(self):
        UDP_packets = self.applyFilters(self.capture,self.UDP_filter)
        return (len(UDP_packets))

    def get_contacted_HTTP_Address(self):
        HTTP_Request_Packets = self.applyFilters(self.capture,self.HTTP_request)
        urls = []
        for pkt in HTTP_Request_Packets:
            header_raw = pkt.load
            try:
                header_line,header_data = header_raw.split("\r\n",1)
            except ValueError:
                pass
            headers = Message(StringIO(header_data))
            uri =  header_line.strip("HTTP/1.1").strip("GET").lstrip().rstrip()
            url = headers["host"]+uri
            urls.append(url)
        return urls

    def count_http_redirects(self):
        HTTP_Request_Packets = self.applyFilters(self.capture,self.HTTP_redirects)
        count = 0
        for pkt in HTTP_Request_Packets:
            header_raw = pkt.load
            try:
                header_line,header_data = header_raw.split("\r\n",1)
            except ValueError:
                pass
            if "HTTP/1.1 302" in header_line:
                count=count+1
        return count

    def get_biggest_HTTP_packet_data(self):
        http_response_packets = self.applyFilters(self.capture,self.HTTP_payloadSize)
        data_dict = {}
        for pkt in http_response_packets:
            pkt_payload_size = len(pkt["Raw"])
            data_dict[str(pkt_payload_size)] = str(pkt["Raw"])
        max_packet_element = max(data_dict.keys())
        try:
            return unicode(data_dict[max_packet_element])
        except UnicodeDecodeError:
            return "Data cannot be formatted in Unicode, probably Image file of size %d"%pkt_payload_size

    def get_Syn_Requests(self):
        TCP_syn_packets = self.applyFilters(self.capture,self.TCP_SYN)
        IP_Addresses_communicated = set()
        for pkt in TCP_syn_packets:
            if pkt["TCP"].flags == 2:
                IP_Addresses_communicated.add(pkt["IP"].dst)
        return IP_Addresses_communicated


if __name__ == "__main__":
    pcap = ParsePackets("msn_all.pcap")
    parsing_pcap = {}
    parsing_pcap["Number_of_TCP_Packets"] = pcap.count_TCP_Packets()
    parsing_pcap["Number_of_UDP_Packets"] = pcap.count_UDP_Packets()
    parsing_pcap["Number_of_HTTP_Redirects"] = pcap.count_http_redirects()
    parsing_pcap["IP_communicated"] = list(pcap.get_Syn_Requests())
    parsing_pcap["Contacted_URLs"] = pcap.get_contacted_HTTP_Address()
    parsing_pcap["biggest_payload_data"] = pcap.get_biggest_HTTP_packet_data()
    with open("scapy_output.json","w") as outfile:
        json.dump(parsing_pcap,outfile)
