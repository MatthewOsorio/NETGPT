from pyshark import FileCapture
from src.packet import packet
from src.protocols.linklayer import ethernet, arp
from src.protocols.networklayer import ipv4, ipv6
from src.protocols.transportlayer import tcp, udp
from src.protocols.applicationlayer import dns_query, dns_response, tls,http

class fileprocessor:
    def __init__(self, file):
        self.capture = FileCapture(file, display_filter='eth or arp or ip or ipv6 or tcp or udp or dns or http or tls')
        self.packets= []
        self.max_packets=280
        
    def getPackets(self):
        return self.packets

    def process(self):
        count=0
        for pack in self.capture:
            if pack.highest_layer == 'QUIC':
                continue

            if count == self.max_packets:
                break
                
            new_packet = packet()
            new_packet.setPacketNum(int(pack.number))
            new_packet.setPacketSize(int(pack.length))

            #Link Layer
            if 'ETH' in pack:
                eth= ethernet.ethernet()
                eth.setSourceMacAddr(pack.eth.src)
                eth.setDestMacAddr(pack.eth.dst)
                eth.setEtherType(pack.eth.type)

                if 'ARP' in pack:
                    link_arp= arp.arp()
                    link_arp.setOPCode(pack.arp.opcode)
                    link_arp.setSenderIPAddr(pack.arp.src_proto_ipv4)
                    link_arp.setSenderMacAddr(pack.arp.src_hw_mac)
                    link_arp.setTargetIPAddr(pack.arp.dst_proto_ipv4)
                    link_arp.setTargetMacAddr(pack.arp.dst_hw_mac)
                    eth.setARP(link_arp)

                new_packet.setLinkLayer(eth)
                new_packet.setLLProtocol('eth')
            
            #Netork Layer
            if 'IP' in pack:
                ip = ipv4.ipv4()
                ip.setSourceIPAddr(pack.ip.src)
                ip.setDestIPAddr(pack.ip.dst)
                ip.setTTL(int(pack.ip.ttl))

                new_packet.setNetLayer(ip)
                new_packet.setNLProtocol('IP')

            if 'IPV6' in pack:
                ip2= ipv6.ipv6()
                ip2.setSourceIPAddr(pack.ipv6.src)
                ip2.setDestIPAddr(pack.ipv6.dst)
                ip2.setTrafficClass(pack.ipv6.tclass)

                new_packet.setNetLayer(ip2)
                new_packet.setNLProtocol('IPv6')

            #Transport Layer
            if 'TCP' in pack:
                tran_tcp= tcp.tcp()
                tran_tcp.setSrcPort(int(pack.tcp.port))
                tran_tcp.setDSTPort(int(pack.tcp.dstport))
                tran_tcp.setFlags(pack.tcp.flags)
                tran_tcp.setSeqNum(int(pack.tcp.seq))
                tran_tcp.setAckNum(int(pack.tcp.ack))

                new_packet.setTranLayer(tran_tcp)
                new_packet.setTLProtocol('TCP')

            if 'UDP' in pack:
                tran_udp= udp.udp()
                tran_udp.setSrcPort(int(pack.udp.port))
                tran_udp.setDstPort(int(pack.udp.dstport))
                tran_udp.setChecksum(pack.udp.checksum)
                tran_udp.setLength(int(pack.udp.length))

                new_packet.setTranLayer(tran_udp)
                new_packet.setTLProtocol('UDP')

            #Application Layer
            if 'DNS' in pack:
                if pack.dns.flags_response == 'False':
                    dns_q= dns_query.dns_query()
                    dns_q.setID(pack.dns.id)
                    dns_q.setName(pack.dns.qry_name)
                    dns_q.setType(int(pack.dns.qry_type))

                    new_packet.setAppLayer(dns_q)
                    new_packet.setALProtocol('DNS Query')

                else:
                    dns_r = dns_response.dns_response()
                    dns_r.setID(pack.dns.id)
                    dns_r.setRCode(int(pack.dns.flags_rcode))
                    
                    dns_r_ans=''

                    if hasattr(pack.dns, "a"):
                        dns_r_ans += str(pack.dns.a) + ','
                    if hasattr(pack.dns, "aaaa"):
                        dns_r_ans += str(pack.dns.aaaa) + ','
                    if hasattr(pack.dns, 'https'):
                        dns_r_ans += str(pack.dns.https) + ','
                    if hasattr(pack.dns, 'http'):
                        dns_r_ans += str(pack.dns.http) + ','
                    if hasattr(pack.dns, 'cname'):
                        dns_r_ans += str(pack.dns.cname) + ','
                    if hasattr(pack.dns, 'mx'):
                        dns_r_ans += str(pack.dns.mx) + ','
                    
                    dns_r.setAnswers(dns_r_ans)

                    new_packet.setAppLayer(dns_r)
                    new_packet.setALProtocol('DNS Response')

            if 'TLS' in pack:
                if hasattr(pack.tls, 'handshake_type'):
                    app_tls= tls.tls()
                    app_tls.setVersion(pack.tls.record_version)
                    app_tls.setHSType(int(pack.tls.handshake_type))
                    
                    if hasattr(pack.tls, 'handshake_ciphersuite'):
                        app_tls.setCipherSuite(pack.tls.handshake_ciphersuite)
                    if hasattr(pack.tls, 'handshake_ciphersuites'):
                        app_tls.setCipherSuite(pack.tls.handshake_ciphersuites)
                
                    new_packet.setAppLayer(app_tls)
                    new_packet.setALProtocol("TLS")

            if 'HTTP' in pack:
                app_http= http.http()
                if hasattr(pack.http, 'request_method'):
                    app_http.setRequestMethod(pack.http.request_method)
                    app_http.setURL(pack.http.request_uri)
                    app_http.setHost(pack.http.host)
                    app_http.setUserAgent(pack.http.user_agent)

                    new_packet.setAppLayer(app_http)
                    new_packet.setALProtocol("HTTP Request")
                else:
                    app_http.setStatusCode(int(pack.http.response_code))
                    app_http.setServer(pack.http.server)
                    app_http.setURL(pack.http.request_uri)

                    new_packet.setAppLayer(app_http)
                    new_packet.setALProtocol("HTTP Response")

            count += 1
            new_packet.setHighestLayer()
            self.formatInput(new_packet)
            
    def formatInput(self, pack):
        input_packet={'number': pack.packet_num,
                      'length': pack.packetsize}
        
        if pack.getHighestLayer() == 'link':
            input_packet['link layer'] = {"type": pack.getLLProtocol(),
                                          "src_mac_address": pack.link_layer.getSourceMacAddr(),
                                          "dst_mac_address": pack.link_layer.getDestMacAddr(),
                                          "ethertype": pack.link_layer.getEtherType()}
            if pack.link_layer.hasARP():
                input_packet['arp'] = {'sender_ip_address': pack.link_layer.arp.getSenderIPAddr(),
                                       'sender_mac_address': pack.link_layer.arp.getSenderMacAddr(),
                                       'target_ip_address': pack.link_layer.arp.getTargetIPAddr(),
                                       'target_mac_address': pack.link_layer.arp.getTargetMacAddr(),
                                       'op_code': pack.link_layer.arp.getOPCode()}
                                       
        elif pack.getHighestLayer() == 'network':
            input_packet['link layer'] = {"type": pack.getLLProtocol(),
                                          "src_mac_address": pack.link_layer.getSourceMacAddr(),
                                          "dst_mac_address": pack.link_layer.getDestMacAddr(),
                                          "ethertype": pack.link_layer.getEtherType()}
            if pack.getNLProtocol() == 'IP':
                input_packet['network layer'] = {"type": pack.getNLProtocol(),
                                                 "src_ip_address": pack.network_layer.getSourceIPAddr(),
                                                 "dst_ip_address": pack.network_layer.getDestIPAddr(),
                                                 "time_to_live": pack.network_layer.getTTL()}
            else:
                input_packet['network layer'] = {"type": pack.getNLProtocol(),
                                                 "src_ip_address": pack.network_layer.getSourceIPAddr(),
                                                 "dst_ip_address": pack.network_layer.getDestIPAddr(),
                                                 "traffic_class": pack.network_layer.getTrafficClass()}
                
        elif pack.getHighestLayer() == 'transport':
            input_packet['link layer'] = {"type": pack.getLLProtocol(),
                                          "src_mac_address": pack.link_layer.getSourceMacAddr(),
                                          "dst_mac_address": pack.link_layer.getDestMacAddr(),
                                          "ethertype": pack.link_layer.getEtherType()}
            if pack.getNLProtocol() == 'IP':
                input_packet['network layer'] = {"type": pack.getNLProtocol(),
                                                 "src_ip_address": pack.network_layer.getSourceIPAddr(),
                                                 "dst_ip_address": pack.network_layer.getDestIPAddr(),
                                                 "time_to_live": pack.network_layer.getTTL()}
            else:
                input_packet['network layer'] = {"type": pack.getNLProtocol(),
                                                 "src_ip_address": pack.network_layer.getSourceIPAddr(),
                                                 "dst_ip_address": pack.network_layer.getDestIPAddr(),
                                                 "traffic_class": pack.network_layer.getTrafficClass()}
            if pack.getTLProtocol() == 'TCP':
                input_packet['transport layer'] = {"type": pack.getTLProtocol(),
                                                   "src_port": pack.transport_layer.getSrcPort(),
                                                   "dst_port": pack.transport_layer.getDSTPort(),
                                                   "flags": pack.transport_layer.getFlags(),
                                                   "seq_number": pack.transport_layer.getSeqNum(),
                                                   "ack_number": pack.transport_layer.getAckNum()}
            else:
                input_packet['transport layer'] = {"type": pack.getTLProtocol(),
                                                    "src_port": pack.transport_layer.getSrcPort(),
                                                    "dst_port": pack.transport_layer.getDstPort(),
                                                    "length": pack.transport_layer.getLength(),
                                                    "checksum": pack.transport_layer.getChecksum()}
        else:
            input_packet['link layer'] = {"type": pack.getLLProtocol(),
                                          "src_mac_address": pack.link_layer.getSourceMacAddr(),
                                          "dst_mac_address": pack.link_layer.getDestMacAddr(),
                                          "ethertype": pack.link_layer.getEtherType()}
            if pack.getNLProtocol() == 'IP':
                input_packet['network layer'] = {"type": pack.getNLProtocol(),
                                                 "src_ip_address": pack.network_layer.getSourceIPAddr(),
                                                 "dst_ip_address": pack.network_layer.getDestIPAddr(),
                                                 "time_to_live": pack.network_layer.getTTL()}
            else:
                input_packet['network layer'] = {"type": pack.getNLProtocol(),
                                                 "src_ip_address": pack.network_layer.getSourceIPAddr(),
                                                 "dst_ip_address": pack.network_layer.getDestIPAddr(),
                                                 "traffic_class": pack.network_layer.getTrafficClass()}
            if pack.getTLProtocol() == 'TCP':
                input_packet['transport layer'] = {"type": pack.getTLProtocol(),
                                                   "src_port": pack.transport_layer.getSrcPort(),
                                                   "dst_port": pack.transport_layer.getDSTPort(),
                                                   "flags": pack.transport_layer.getFlags(),
                                                   "seq_number": pack.transport_layer.getSeqNum(),
                                                   "ack_number": pack.transport_layer.getAckNum()}
            else:
                input_packet['transport layer'] = {"type": pack.getTLProtocol(),
                                                    "src_port": pack.transport_layer.getSrcPort(),
                                                    "dst_port": pack.transport_layer.getDstPort(),
                                                    "length": pack.transport_layer.getLength(),
                                                    "checksum": pack.transport_layer.getChecksum()}
                
            if pack.getALProtocol() == 'DNS Query':
                input_packet['application layer'] = {"type": pack.getALProtocol(),
                                                     "id": pack.application_layer.getID(),
                                                     "query_type": pack.application_layer.getType(),
                                                     "query_name": pack.application_layer.getName()}
            elif pack.getALProtocol() == 'DNS Response':
                input_packet['application layer'] = {"type": pack.getALProtocol(),
                                                     "id": pack.application_layer.getID(),
                                                     "response_code": pack.application_layer.getRCode(),
                                                     "answer": pack.application_layer.getAnswers()}
            elif pack.getALProtocol() == 'TLS':
                input_packet['application layer'] = {"type": pack.getALProtocol(),
                                                     "version": pack.application_layer.getVersion(),
                                                     "handshake_type": pack.application_layer.getHSType(),
                                                     "cipher_suite": pack.application_layer.getCipherSuite()}
            elif pack.getALProtocol() == 'HTTP Request':
                input_packet['application layer'] = {"type": pack.getALProtocol(),
                                                     "method": pack.application_layer.getRequestMethod(),
                                                     "url": pack.application_layer.getURL(),
                                                     "host": pack.application_layer.getHost(),
                                                     "user_agent": pack.application_layer.getUserAgent()}
            elif pack.getALProtocol() == 'HTTP Response':
                input_packet['application layer'] = {"type": pack.getALProtocol(),
                                                     "status code": pack.application_layer.getStatusCode(),
                                                     "url": pack.application_layer.getURL(),
                                                     "server": pack.application_layer.getServer()}
            
        self.packets.append(input_packet)