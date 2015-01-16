/******************************************************************************
* Copyright (c) 2005, 2014  Ericsson AB
* All rights reserved. This program and the accompanying materials
* are made available under the terms of the Eclipse Public License v1.0
* which accompanies this distribution, and is available at
* http://www.eclipse.org/legal/epl-v10.html
*
* Contributors:
*   Antal Wuh.Hen.Chang - initial implementation and initial documentation
*   Adam Delic
*   Andrea Darabos
*   Endre Kulcsar
*   Gabor Szalai
*   Tibor Szabo
******************************************************************************/
//
//  File:               PCAPasp_PT.cc
//  Description:        PCAP test port source file
//  Rev:                R7A
//  Prodnr:             CNL 113 443
//

#include "PCAPasp_PT.hh"

#include <TTCN3.hh>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
//#include <openssl/md5.h>
//#include <openssl/hmac.h>
//#include <openssl/aes.h>
//#include <openssl/sha.h>
//#include <openssl/bn.h>


#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>


#include "memory.h"



using namespace PCAPasp__Types;
namespace PCAPasp__PortType{
static const u_int16_t c_infinite = 0xFFFF;
static bool logging = false;
static bool noFilter = false;
static Protocol_data p_data;
static PCAPasp__PT *act_pt;


INTEGER default_getMsgLen(const OCTETSTRING &stream, const BOOLEAN& /*conn__closed*/,
                          const Transport &/*stream__transport*/){
  return stream.lengthof();
}

INTEGER default_getMsgStartPos(const OCTETSTRING &/*stream*/, const BOOLEAN& /*conn__closed*/,
                          const Transport &/*stream__transport*/){
  return 0;
}

static tf__getMsgLen def_getMsgLen_ref=default_getMsgLen;
static tf__getMsgStartPos def_getMsgStartPos_ref=default_getMsgStartPos;

void genlog(const char *fmt, ...) {
	TTCN_Logger::begin_event(TTCN_DEBUG);
	va_list ap;
	va_start(ap, fmt);
	TTCN_Logger::log_event_va_list(fmt, ap);
	va_end(ap); 
	TTCN_Logger::end_event(); 
}

INTEGER f_null_ICV(const OCTETSTRING& /*ipheader*/, const OCTETSTRING& /*ipdata*/, OCTETSTRING& /*user__data*/)
{
return 0;
}

BOOLEAN f_null_encryption(const OCTETSTRING& /*ipheader*/, const OCTETSTRING& ipdata, OCTETSTRING& decrypted__data, OCTETSTRING&/* user__data*/)
{
int ret_len=ipdata.lengthof();
int start_pos=0;
if(ret_len>9){
  int pad_len=((const unsigned char*)ipdata)[ret_len-1];
  ret_len-=9+pad_len;  // spi_length+seq_no_length+pad_length_length = 4+4+1
  if(ret_len<0){
    ret_len=ipdata.lengthof();
  } else {
    start_pos=8;// skip spi+seq_no
  }
}
decrypted__data = OCTETSTRING(ret_len,(const unsigned char*)ipdata+start_pos);
return TRUE;
}

ESP_obj::ESP_obj(PCAPasp__Types::ASP__PCAP__ESP__Setup data){
  spi=data.spi().get_long_long_val();
  if(data.icv__function().ispresent()){
    icv_fv=data.icv__function();
  } else {
    icv_fv=f_null_ICV;
  }
  if(data.icv__function__user__data().ispresent()){
    icv_data=data.icv__function__user__data();
  } else {
    icv_data=OCTETSTRING(0,NULL);
  }
  if(data.esp__decrypt__function().ispresent()){
    decrypt_fv=data.esp__decrypt__function();
  } else {
    decrypt_fv=f_null_encryption;
  }
  if(data.esp__decrypt__function__user__data().ispresent()){
    decrypt_data=data.esp__decrypt__function__user__data();
  } else {
    decrypt_data=OCTETSTRING(0,NULL);
  }
  struct in_addr tmp;
  if(data.sourceIP().ispresent() && inet_aton((const char *)data.sourceIP()(),&tmp)){
    ip_port=std::string((const char *)&tmp,sizeof(tmp));
  } else {
    ip_port=std::string(0,sizeof(tmp));
  }
  if(data.destinationIP().ispresent() && inet_aton((const char *)data.destinationIP()(),&tmp)){
    ip_port+=std::string((const char *)&tmp,sizeof(tmp));
  } else {
    ip_port+=std::string(0,sizeof(tmp));
  }
  u_int16_t tmp2;
  if(data.sourcePort().ispresent()){
    tmp2=htons(data.sourcePort()());
  } else {
    tmp2=0;
  }
  ip_port+=std::string((const char *)&tmp2,sizeof(tmp2));
  if(data.destinationPort().ispresent()){
    tmp2=htons(data.destinationPort()());
  } else {
    tmp2=0;
  }
  ip_port+=std::string((const char *)&tmp2,sizeof(tmp2));
  mode=data.mode();
}
ESP_obj::~ESP_obj(){}


ESP_handler::ESP_handler(){}
ESP_handler::~ESP_handler(){
  clean_up();
}
bool ESP_handler::setup_esp(PCAPasp__Types::ASP__PCAP__ESP__Setup data){
  std::map<unsigned int, ESP_obj*>::iterator it=spi_ESP_obj_map.find(data.spi().get_long_long_val());
  if(data.mode() == PCAPasp__Types::ESP__mode::ESP__DELETE){
    if(it==spi_ESP_obj_map.end()){
      return false;
    }
    address_ESP_obj_map.erase((it->second)->ip_port);
    for (std::list<ESP_obj*>::iterator it2=ESP_OBJ_list.begin(); it2 != ESP_OBJ_list.end(); ++it2){
      if(*it2 == it->second) {
        ESP_OBJ_list.erase(it2);
        break;
      }
    }
    delete it->second;
    spi_ESP_obj_map.erase(it);
    return true;
  } else {
    if(it!=spi_ESP_obj_map.end()){
      return false;
    }
    ESP_obj* new_esp=new ESP_obj(data);
    if(address_ESP_obj_map.find(new_esp->ip_port)!=address_ESP_obj_map.end()){
      delete new_esp;
      return false;
    }
    address_ESP_obj_map[new_esp->ip_port]=new_esp;
    spi_ESP_obj_map[new_esp->spi]=new_esp;
    ESP_OBJ_list.push_back(new_esp);
    return true;
  }

  return false;
}
bool ESP_handler::find_esp(unsigned int spi, ESP_obj *& esp){
  std::map<unsigned int, ESP_obj*>::iterator it=spi_ESP_obj_map.find(spi);
  if(it==spi_ESP_obj_map.end()){
    return false;
  }
  esp=it->second;
  return true;
}
bool ESP_handler::esp_exists(struct in_addr *ip_src, unsigned int port_src,struct in_addr *ip_dst,unsigned int port_dst,unsigned int /*proto*/){
  u_int16_t p_src=port_src;
  u_int16_t p_dst=port_dst;
  if(address_ESP_obj_map.find(std::string((const char *)ip_src,sizeof(ip_src))+
                              std::string((const char *)ip_dst,sizeof(ip_dst))+
                              std::string((const char *)&p_src,sizeof(p_src))+
                              std::string((const char *)&p_dst,sizeof(p_dst))
                                                                      )!=address_ESP_obj_map.end()){
    return true;
  }
  if(address_ESP_obj_map.find(std::string((const char *)ip_src,sizeof(ip_src))+
                              std::string((const char *)ip_dst,sizeof(ip_dst))+
                              std::string(2,'\0')+
                              std::string((const char *)&p_dst,sizeof(p_dst))
                                                                      )!=address_ESP_obj_map.end()){
    return true;
  }
  if(address_ESP_obj_map.find(std::string((const char *)ip_src,sizeof(ip_src))+
                              std::string((const char *)ip_dst,sizeof(ip_dst))+
                              std::string((const char *)&p_src,sizeof(p_src))+
                              std::string(2,'\0')
                                                                      )!=address_ESP_obj_map.end()){
    return true;
  }
  if(address_ESP_obj_map.find(std::string(4,'\0')+
                              std::string((const char *)ip_dst,sizeof(ip_dst))+
                              std::string(2,'\0')+
                              std::string((const char *)&p_dst,sizeof(p_dst))
                                                                      )!=address_ESP_obj_map.end()){
    return true;
  }
  if(address_ESP_obj_map.find(std::string(4,'\0')+
                              std::string((const char *)ip_dst,sizeof(ip_dst))+
                              std::string(2,'\0')+
                              std::string((const char *)&p_dst,sizeof(p_dst))
                                                                      )!=address_ESP_obj_map.end()){
    return true;
  }
  
  return false;
}
void ESP_handler::clean_up(){
  spi_ESP_obj_map.clear();
  address_ESP_obj_map.clear();
  for (std::list<ESP_obj*>::iterator it=ESP_OBJ_list.begin(); it != ESP_OBJ_list.end(); ++it){
    delete *it;
  }
  ESP_OBJ_list.clear();
}

bool ESP_handler::match_esp(struct in_addr *ip_src, unsigned int port_src,struct in_addr *ip_dst,unsigned int port_dst,const ESP_obj *esp){
  u_int16_t p_src=port_src;
  u_int16_t p_dst=port_dst;
  return (esp->ip_port.substr(0,4)==std::string(4,'\0') || esp->ip_port.substr(0,4)==std::string((const char *)ip_src,sizeof(ip_src))) &&
         (esp->ip_port.substr(4,4)==std::string(4,'\0') || esp->ip_port.substr(4,4)==std::string((const char *)ip_dst,sizeof(ip_dst))) &&
         (esp->ip_port.substr(8,2)==std::string(2,'\0') || esp->ip_port.substr(8,2)==std::string((const char *)&p_src,sizeof(p_src))) &&
         (esp->ip_port.substr(8,2)==std::string(2,'\0') || esp->ip_port.substr(8,2)==std::string((const char *)&p_dst,sizeof(p_dst)));
}

////////////////////////////////////////////////////////////
// Constructor
////////////////////////////////////////////////////////////
PCAPasp__PT::PCAPasp__PT(const char *par_port_name)
	: PCAPasp__PT_BASE(par_port_name)
{
  capture_file = NULL;
  packet_filter = new char[1]; packet_filter[0] = '\0';
  logging = false;
  handle = NULL;
  dumpfile = NULL;
  
  
  //for debugging:
  peer_list_tcp.setType(true);
  peer_list_udp.setType(false);
  peer_list_sctp.setType(false);
}


////////////////////////////////////////////////////////////
// Destructor
////////////////////////////////////////////////////////////
PCAPasp__PT::~PCAPasp__PT()
{
  if (capture_file) delete [] capture_file;
  if (packet_filter) delete [] packet_filter;
}


////////////////////////////////////////////////////////////
// set_parameter
////////////////////////////////////////////////////////////
void PCAPasp__PT::set_parameter(const char *parameter_name,
	const char *parameter_value)
{
  //Capturing related parameters
  if (strcmp("capture_file", parameter_name) == 0) {
    if (capture_file) delete [] capture_file;
    capture_file = new char[strlen(parameter_value) + 1];
    strcpy(capture_file, parameter_value);
  }
  else if (strcmp("packet_filter", parameter_name) == 0) {
    if (packet_filter) delete [] packet_filter;
    packet_filter = new char[strlen(parameter_value) + 1];
    strcpy(packet_filter, parameter_value);
  }
  else if (strcmp("logging", parameter_name) == 0) {
    
    if (strcasecmp(parameter_value, "TRUE") == 0) {
      logging = true;
    }
    else logging = false;
  }
  else if (strcmp("noFilter", parameter_name) == 0) {
    
    if (strcasecmp(parameter_value, "TRUE") == 0) {
      noFilter = true;
    }
    else noFilter = false;
  }
  else
    TTCN_warning("PCAP Test Port(%s): Invalid parameter: %s.",port_name ,parameter_name);
}


////////////////////////////////////////////////////////////
// Event_Handler
////////////////////////////////////////////////////////////
void PCAPasp__PT::Event_Handler(const fd_set */*read_fds*/, const fd_set */*write_fds*/, const fd_set */*error_fds*/, double /*time_since_last_call*/)
{
  const u_char* packet;
  packet = pcap_next( handle, &header);
  
  if (packet == NULL)
    TTCN_error("PCAP can't capture");
  if (capture)
    pcap_dump((u_char*)dumpfile, &header, packet);
}


////////////////////////////////////////////////////////////
// user_map
////////////////////////////////////////////////////////////
void PCAPasp__PT::user_map(const char */*system_port*/)
{
  if( geteuid() != 0 ) TTCN_warning ( "You must be root to be able to use the test port in capturing mode!");
  capture = 0;
  settings = 0;
        
  if (capture_file!=NULL){
    if (dump_reader.open(capture_file)==false) {
      TTCN_error("Failed to open capture file \"%s\"", capture_file);
      return;
    }
    else {
      log("Capture file \"%s\" was opened", capture_file);
    }
  }
  
  if (packet_filter!=NULL){
    if (dump_reader.setFilter(packet_filter)==false) {
      TTCN_error("Failed to set the packet filter %s", packet_filter);
      return;
    } else {
      log("Filter \"%s\" was applied", packet_filter);
    }
  }
}


////////////////////////////////////////////////////////////
// user_unmap
////////////////////////////////////////////////////////////
void PCAPasp__PT::user_unmap(const char */*system_port*/)
{
  peer_list_tcp.log_stat();
  Uninstall_Handler();
  if (handle) pcap_close( handle);
  if (dumpfile) pcap_dump_close( dumpfile);
}

void PCAPasp__PT::user_start()
{

}

void PCAPasp__PT::user_stop()
{

}


////////////////////////////////////////////////////////////
// outgoing_send
////////////////////////////////////////////////////////////
void PCAPasp__PT::outgoing_send(const PCAPasp__Types::ASP__PCAP__ESP__Setup& send_par){
  PCAPasp__Types::ASP__PCAP__ESP__Setup__Resp ret_val;
  if(esp.setup_esp(send_par)){
    ret_val.status__code()=PCAPasp__Types::ESP__Status::ESP__OK;
    ret_val.status__message()=OMIT_VALUE;
  } else {
    ret_val.status__code()=PCAPasp__Types::ESP__Status::ESP__SETUP__ERROR;
    ret_val.status__message()="Failed to register the ESP";
  }
  incoming_message(ret_val);
}

void PCAPasp__PT::outgoing_send(const PCAPasp__Types::ASP__PCAP__Capture& send_par)
{
  PCAPasp__Types::ASP__PCAP__ConfigResp myStatus;
  fd_set readfds;
  
  myStatus.status() = CommandStatus::INVALID;
  myStatus.errorMessage() = OMIT_VALUE;

  if( send_par.command() == CaptureControl::START ) {
    myStatus.command() = CommandId::STARTCMD;
    if (settings) {
      if (capture) {
        myStatus.errorMessage() = CommandError::CAPTURING__HAS__ALREADY__STARTED;
      }
      else {
        myStatus.status() = CommandStatus::VALID;
	capture = 1;
	FD_ZERO( &readfds);
	FD_SET( pcap_fileno( handle), &readfds ); 
	Install_Handler( &readfds, NULL, NULL, 0.0 );
     }
   }
   else {
     myStatus.errorMessage() = CommandError::THERE__IS__NO__FILTER__SET;
   }	
 }
 
 else if( send_par.command() == CaptureControl::STOP ) {
   myStatus.command() = CommandId::STOPCMD;
   if (capture) {
     myStatus.status() = CommandStatus::CommandStatus::VALID;
     capture = 0;
   }
   else {
     myStatus.errorMessage() = CommandError::CAPTURING__HAS__NOT__STARTED;
   }
 }
 incoming_message( myStatus );
}

////////////////////////////////////////////////////////////
// outgoing_send
////////////////////////////////////////////////////////////
void PCAPasp__PT::outgoing_send(const PCAPasp__Types::ASP__PCAP__ConfigReq& send_par) {

  struct bpf_program filter;
  char errbuf[PCAP_ERRBUF_SIZE];
  bpf_u_int32 mask;
  bpf_u_int32 net;
    
  CHARSTRING myInterface;
  CHARSTRING myFilter;
  INTEGER myMask;
  PCAPasp__Types::ASP__PCAP__ConfigResp myStatus;

  myStatus.command() = CommandId::FILTERCMD;
  myStatus.status() = CommandStatus::INVALID;
  myStatus.errorMessage() = OMIT_VALUE;

  if (capture) {
    myStatus.errorMessage() = CommandError::PORT__IS__ALREADY__CAPTURING;
  }
  else {
    settings = 0;

    Uninstall_Handler();
    if( dumpfile != NULL){
           pcap_dump_close( dumpfile);
           dumpfile = NULL;
    }

    if (send_par.interface().ispresent()) myInterface = send_par.interface();
    else myInterface = "eth0";

    if (send_par.filter().ispresent()) myFilter = send_par.filter();
    else myFilter = "";

    if (send_par.mask().ispresent()) myMask = send_par.mask();
    else myMask = 0xffffff;

    char* myFilterString = new char[strlen(myFilter) + 1];
    strcpy(myFilterString, (const char*)myFilter);

    if( pcap_lookupnet( myInterface, &net, &mask, errbuf) == -1){
           myStatus.errorMessage() = CommandError::ERROR__LOOKING__NET__UP;
    }
    else {
      handle = pcap_open_live( myInterface, 1514, 1, 0, errbuf);	
      if( handle == NULL ){
             myStatus.errorMessage() = CommandError::ERROR__LIVE__OPENING;
      }
      else if( pcap_compile( handle, &filter, myFilterString, 0, myMask) == -1){
             myStatus.errorMessage() = CommandError::ERROR__COMPILING__FILTER;
      }
      else if( pcap_setfilter( handle, &filter) == -1 ){
             myStatus.errorMessage() = CommandError::ERROR__SETTING__FILTER;
      }
      else if( pcap_setnonblock( handle, 1, errbuf) == -1 ){
             myStatus.errorMessage() = CommandError::ERROR__SETTING__NONBLOCK__MODE;
      }
      else {
        dumpfile = pcap_dump_open( handle, (const char*)send_par.filename());
        if( dumpfile == NULL) {
          myStatus.errorMessage() = CommandError::ERROR__OPENING__OUTPUT__FILE;
        }
        else {
          settings = 1;
          myStatus.status() = CommandStatus::CommandStatus::VALID;
        }
      }
    }
    
    if (myFilterString) delete [] myFilterString;
  }
  incoming_message( myStatus );
}

////////////////////////////////////////////////////////////
// outgoing_send
////////////////////////////////////////////////////////////
void PCAPasp__PT::outgoing_send(const PCAPasp__Types::ASP__PCAP__DumpReaderFilter& send_par)
{
    PCAPasp__Types::ASP__PCAP__DumpFilterResp respStatus;
    struct in_addr srcIp;
    struct in_addr destIp;
    in_addr_t addr;
    bool srcIpAll = false;
    int trueFlag = 1;
    memset(&srcIp, 0, sizeof(srcIp));
    respStatus.status() = CommandStatus::CommandStatus::VALID;
    respStatus.errorMessage() = OMIT_VALUE;

        if (strcmp(send_par.localIp(), "*")==0)
        {
          srcIpAll = true;
        }
        else
        {
          addr = inet_addr( send_par.localIp() );
	  
	  if (addr != (in_addr_t)-1)
		  memcpy(&(srcIp.s_addr), &addr, sizeof(addr));
	  else{
	      trueFlag = 0;
	      respStatus.status() = CommandStatus::INVALID;
	      respStatus.errorMessage() = DumpFilterError::WRONG__SOURCE__IP;
	  }
        }
	
	addr = inet_addr( send_par.remoteIp() );
	
	if (addr != (in_addr_t)-1)
		memcpy(&(destIp.s_addr), &addr, sizeof(addr));
	else{
	    trueFlag = 0;
	    respStatus.status() = CommandStatus::INVALID;
	    respStatus.errorMessage() = DumpFilterError::WRONG__DESTINATION__IP;
	}
	
	if( trueFlag ){
          for (int i=0; i<send_par.remotePorts().size_of(); i++) {
            int port = (int) ( send_par.remotePorts()[i] );
            filter_table.addEntry((int)send_par.messageType(), srcIp, srcIpAll, destIp, (unsigned int) port);
          }
	}
	
    incoming_message( respStatus );
}

////////////////////////////////////////////////////////////
// outgoing_send
////////////////////////////////////////////////////////////
void PCAPasp__PT::outgoing_send(const PCAPasp__Types::ASP__PCAP__MessageReq& send_par)
{
  PCAPasp__Types::ASP__PCAP__MessageResp incoming_msg;
  TCPSegment* seg = NULL;
  bool ready_message = false;
  bool no_more_message = false;
  
  do {
    Peer* act_peer;
    for (int i=0; i<peer_list_tcp.length(); i++) {
      act_peer = peer_list_tcp.elementAt(i);
      int embedded_length=0;
      if (act_peer->tcp_buf.length > 0) { // is there anything in the buffer?
log("peer_list_tcp, peer %d", i);
        embedded_length=act_peer->get_msg_len();
log("peer_list_tcp, embedded_length %d", embedded_length);
        if(embedded_length>0){
          if (send_par.nextMessage() == act_peer->protocol_type || send_par.nextMessage() == -1) {
            ready_message=true;
            incoming_msg.status() = Status::VALID__MESSAGE;
            incoming_msg.timeStamp() = act_peer->tcp_buf.timestamp;
            incoming_msg.contentLength() = embedded_length;
            incoming_msg.sourcePort() = act_peer->port_src;
            incoming_msg.destinationPort() = act_peer->port_dst;
            incoming_msg.sourceIP() = inet_ntoa(act_peer->ip_src);
            incoming_msg.destinationIP() = inet_ntoa(act_peer->ip_dst);
            incoming_msg.msgtype()=act_peer->protocol_type;
            incoming_msg.nextMessage()=OCTETSTRING(embedded_length,act_peer->tcp_buf.get_read_data());
            incoming_message(incoming_msg);
          }
          act_peer->tcp_buf.set_pos(act_peer->tcp_buf.get_pos()+embedded_length);
          act_peer->tcp_buf.cut();
        }
      } // if peer's buffer > 0
      if(embedded_length<=0 && act_peer->tcp_buf.closed && !act_peer->tcp_buf.close_sent){
        act_peer->tcp_buf.close_sent=true;
          ASP__PCAP__ConnectionClosed apcc_msg;
          apcc_msg.protocol() = act_peer->protocol_type;
          apcc_msg.destinationPort() = act_peer->port_dst;
          apcc_msg.destinationIP() = inet_ntoa(act_peer->ip_dst);
          apcc_msg.sourcePort() = act_peer->port_src;
          apcc_msg.sourceIP() = inet_ntoa(act_peer->ip_src);
          incoming_message(apcc_msg);
      }
      if(ready_message) break;
    } // for each tcp peer


    if (!ready_message) //if no requested message was found we iterate through the UDP streams as well.
    for (int i=0; i<peer_list_udp.length(); i++) {
      act_peer = peer_list_udp.elementAt(i);
      
      if (act_peer->tcp_buf.length > 0) { // is there anything in the buffer?
        int embedded_length=act_peer->get_msg_len();
        if(embedded_length>0){
          if (send_par.nextMessage() == act_peer->protocol_type || send_par.nextMessage() == -1) {
            ready_message=true;
            incoming_msg.status() = Status::VALID__MESSAGE;
            incoming_msg.timeStamp() = act_peer->tcp_buf.timestamp;
            incoming_msg.contentLength() = embedded_length;
            incoming_msg.sourcePort() = act_peer->port_src;
            incoming_msg.destinationPort() = act_peer->port_dst;
            incoming_msg.sourceIP() = inet_ntoa(act_peer->ip_src);
            incoming_msg.destinationIP() = inet_ntoa(act_peer->ip_dst);
            incoming_msg.msgtype()=act_peer->protocol_type;
            incoming_msg.nextMessage()=OCTETSTRING(embedded_length,act_peer->tcp_buf.get_data());
            incoming_message(incoming_msg);
          }
          act_peer->tcp_buf.set_pos(embedded_length);
          act_peer->tcp_buf.cut();
        }
      } // if peer's buffer > 0
      if(ready_message) break;
    } // for each udp peer

    if (!ready_message) //if no requested message was found we iterate through the SCTP streams as well.
    for (int i=0; i<peer_list_sctp.length(); i++) {
      act_peer = peer_list_sctp.elementAt(i);
      
      if (act_peer->has_message()) { // is there anything in the buffer?
        int embedded_length=act_peer->get_first_sctp_data_len();
        if(embedded_length>0){
          if (send_par.nextMessage() == act_peer->protocol_type || send_par.nextMessage() == -1) {
            ready_message=true;
            incoming_msg.status() = Status::VALID__MESSAGE;
            incoming_msg.timeStamp() = act_peer->get_first_sctp_timestamp();
            incoming_msg.contentLength() = embedded_length;
            incoming_msg.sourcePort() = act_peer->port_src;
            incoming_msg.destinationPort() = act_peer->port_dst;
            incoming_msg.sourceIP() = inet_ntoa(act_peer->ip_src);
            incoming_msg.destinationIP() = inet_ntoa(act_peer->ip_dst);
            incoming_msg.msgtype()=act_peer->protocol_type;
            incoming_msg.nextMessage()=OCTETSTRING(embedded_length,act_peer->get_first_sctp_data());
            incoming_message(incoming_msg);
          }
          act_peer->delete_first_sctp_message();
        }
      } // if peer's buffer > 0
      if(ready_message) break;
    } // for each sctp peer

    if (!ready_message) {
      
      act_pt=this;
      seg = getNextFilteredSegment();
      if (seg) { 
      
        seg->log();
        
        if (seg->seg_type == SCTP_SEG && seg->fin) { //PCAP_ASP_ConnectionClosed must be sent to TTCN in case a TCP connection is terminated
          ASP__PCAP__ConnectionClosed apcc_msg;
          apcc_msg.protocol() = seg->protocol_type;
          apcc_msg.destinationPort() = seg->port_dst;
          apcc_msg.destinationIP() = inet_ntoa(seg->ip_dst);
          apcc_msg.sourcePort() = seg->port_src;
          apcc_msg.sourceIP() = inet_ntoa(seg->ip_src);
          incoming_message(apcc_msg);
        }
        
        if (seg->seg_type == TCP_SEG) {
            INTEGER port_dst = seg->port_dst;
            INTEGER port_src = seg->port_src;
            CHARSTRING ip_src = inet_ntoa(seg->ip_src);
            CHARSTRING ip_dst = inet_ntoa(seg->ip_dst);
          if (!peer_list_tcp.sendSegmentToPeer(seg)) {
            //We detected a lost segment.
            //Note that, the source and destination directions are exchanged
            //because the lost segment was in other direction than the acknowledgment
            //via we detected it.
            ASP__PCAP__Error ape;
            ape.errorType() = PCAPError::LOST__SEGMENT;
            ape.sourcePort() = port_dst;
            ape.destinationPort() = port_src;
            ape.sourceIP() = ip_dst;
            ape.destinationIP() = ip_src;
            incoming_message(ape);
          }
        }
        else if (seg->seg_type == UDP_SEG) {
          peer_list_udp.sendSegmentToPeer(seg);
        } 
        else if (seg->seg_type == SCTP_SEG) {
            INTEGER port_dst = seg->port_dst;
            INTEGER port_src = seg->port_src;
            CHARSTRING ip_src = inet_ntoa(seg->ip_src);
            CHARSTRING ip_dst = inet_ntoa(seg->ip_dst);
          if (!peer_list_sctp.sendSegmentToPeer(seg)) {
            //We detected a lost segment.
            //Note that, the source and destination directions are exchanged
            //because the lost segment was in other direction than the acknowledgment
            //via we detected it.
            ASP__PCAP__Error ape;
            ape.errorType() = PCAPError::LOST__SEGMENT;
            ape.sourcePort() = port_dst;
            ape.destinationPort() = port_src;
            ape.sourceIP() = ip_dst;
            ape.destinationIP() = ip_src;
            incoming_message(ape);
          }
        }
      }
      else no_more_message = true;
    }
    
  } while (!no_more_message && !ready_message);
  
  //No more messages in the dump file
  if (no_more_message) {
    incoming_msg.status() = Status::NO__MESSAGE;
    incoming_msg.timeStamp() = OMIT_VALUE;
    incoming_msg.contentLength() = OMIT_VALUE;
    incoming_msg.sourcePort() = OMIT_VALUE;
    incoming_msg.destinationPort() = OMIT_VALUE;
    incoming_msg.sourceIP() = OMIT_VALUE;
    incoming_msg.destinationIP() = OMIT_VALUE;
    incoming_msg.msgtype()= OMIT_VALUE;
    incoming_msg.nextMessage() = OMIT_VALUE;
    incoming_message(incoming_msg);
    if (logging){
     log("stream buffers:");
     peer_list_tcp.dump();
     peer_list_udp.dump();
    }
  }
}

void PCAPasp__PT::outgoing_send(const PCAPasp__Types::ASP__PACP__SetupProtocol& send_par){
  p_data.add_protocol(send_par.protocol__id(),
  send_par.getMsgLen__function().ispresent()?send_par.getMsgLen__function()():default_getMsgLen,
  send_par.getMsgStartPos__function().ispresent()?send_par.getMsgStartPos__function()():default_getMsgStartPos

                      );
}



////////////////////////////////////////////////////////////
// getNextFilteredSegment
////////////////////////////////////////////////////////////
TCPSegment* PCAPasp__PT::getNextFilteredSegment()
{
  TCPSegment* seg = NULL;
  int protocol_type;
  bool found = false;
  bool last = false;
  
  do {
    seg = dump_reader.getNextSegment();
    if (seg) {
      protocol_type = filter_table.filter(seg);
      log("Check protocol");
      if (protocol_type != NO_PROTOCOL) {
      log("found protocol");
        seg->protocol_type = protocol_type;
        found = true;
      }
      else {
      log("no protocol");
        delete seg; seg = NULL;
      }
    }
    else {
      last = true;
    }
  }
  while (!found && !last);
  return seg;
}

void PCAPasp__PT::log(const char *fmt, ...) { 
  TTCN_Logger::begin_event(TTCN_DEBUG);
  TTCN_Logger::log_event("PCAPasp_PT: ");
  va_list ap;
  va_start(ap, fmt);
  TTCN_Logger::log_event_va_list(fmt, ap);
  va_end(ap); 
  TTCN_Logger::end_event(); 
}



////////////////////////////////////////////////////////////
// TCPSegment implementation
////////////////////////////////////////////////////////////
TCPSegment::TCPSegment()
{
  payload = NULL;
  length = 0;
  syn = false; fin = false;
  seq_num = 0;
  ack_num = 0;
  seg_type = TCP_SEG;
  protocol_type = NO_PROTOCOL;
  timestamp = 0.0;
}

TCPSegment::~TCPSegment()
{
  if (payload) delete [] payload;
}

void TCPSegment::put(char* buf, size_t size)
{
  if (size>0) {
    if (payload) delete [] payload;
    payload = new unsigned char[size];
    memcpy(payload, buf, size);
    length = size;
  }
  else {
    if (payload) delete [] payload;
    payload = NULL;
    length = 0;
  }
}

void TCPSegment::log(const char *fmt, ...) {
	TTCN_Logger::begin_event(TTCN_DEBUG);
	TTCN_Logger::log_event("TCPSegment: ");
	va_list ap;
	va_start(ap, fmt);
	TTCN_Logger::log_event_va_list(fmt, ap);
	va_end(ap); 
	TTCN_Logger::end_event(); 
}

void TCPSegment::log() {
  TTCN_Logger::begin_event(TTCN_DEBUG);
  TTCN_Logger::log_event("-=> TCPSegment object: \n");
  TTCN_Logger::log_event("address %p ¦n", this);
  TTCN_Logger::log_event("IP src: %s ", inet_ntoa(ip_src));
  TTCN_Logger::log_event("dst: %s\n", inet_ntoa(ip_dst));
  TTCN_Logger::log_event("Port src: %d dst: %d\n", port_src, port_dst);
  switch (seg_type) {
    case UDP_SEG:
      TTCN_Logger::log_event("UDP segment len:%zu\n", length);
      break;
    case TCP_SEG:
      TTCN_Logger::log_event("TCP segment len:%zu seq:%lu ack:%lu", length, seq_num, ack_num);
      if (syn) TTCN_Logger::log_event(" SYN\n"); else TTCN_Logger::log_event("\n");
      break;
  }
  u_char* dataptr = (u_char*) payload;
  for (u_int i=1; i<length+1; i++) {
    TTCN_Logger::log_event("%.2x ", dataptr[i-1]);
    if (i%16==0) TTCN_Logger::log_event("\n");
  }
  TTCN_Logger::log_event("\n");
  TTCN_Logger::end_event();
}


////////////////////////////////////////////////////////////
// DumpReader implementation
////////////////////////////////////////////////////////////
DumpReader::DumpReader () {
  fp = NULL;
  frameCounter = 1;
}

DumpReader::~DumpReader() {
  if (fp) pcap_close(fp);
}

bool DumpReader::open(char* fname) {
  if ( (fp = pcap_open_offline(fname, errbuf) ) == NULL) {
    TTCN_warning("Error message received: %s", errbuf);
    return false;
  }
  return true;
}

bool DumpReader::getNext() {
  if (fp) {
    genlog("DumpReader: Frame: %d", frameCounter); frameCounter++;
    int res = pcap_next_ex( fp, &actHeader, &actData);
    if ( res >= 0) return true;
    else {
        if(res == -1) {
          TTCN_warning("Error reading the packets: %s", pcap_geterr(fp));
        }
      return false;
    }
  }
  else {
    TTCN_warning("No capture file is set");
    return false;
  }
}

bool DumpReader::setFilter(char* filter_script, bpf_u_int32 netmask) {
  if (strlen(filter_script) != 0) {
    if(pcap_compile(fp, &BPFcode, filter_script, 1, netmask)<0) {
      TTCN_warning("Unable to compile the filter. check the syntax: %s", filter_script);
      return false;
    }
    if(pcap_setfilter(fp, &BPFcode)<0) {
      TTCN_warning("Error setting the filter: %s", filter_script);
      return false;
    }
  }
  return true;
}

bool DumpReader::getNextEthernet() {
  bool ether_found = false;
  while (!ether_found) {
    if (this->getNext())
    {
      struct ::ether_header* ether_ptr;
      ether_ptr = (struct ::ether_header *) actData;
      if ( ntohs (ether_ptr->ether_type) == ETHERTYPE_IP )
      {
        ether_found = true;
	actEthernetHeader = ether_ptr;
	actEthernetData = (u_char*) actData;
	actEthernetData += sizeof(struct ::ether_header);
        return true;
      }
      else if ( ntohs (ether_ptr->ether_type) == PCAP_ETHERTYPE_VLAN8021Q )
      {
        struct vlan_header* vlan_ptr;
        vlan_ptr = (struct vlan_header*) ((u_char*)actData + sizeof(struct ::ether_header));
        if (ntohs(vlan_ptr->vlan_type) == ETHERTYPE_IP)
        {
          ether_found = true;
	  actEthernetHeader = ether_ptr;
	  actEthernetData = (u_char*) actData;
	  actEthernetData += sizeof(struct ::ether_header) + sizeof(vlan_header);
          return true;
        }
        else TTCN_warning("Not an IP datagram in VLAN 802.1Q packet");
      }
      else
      {
        TTCN_warning("Not an IP datagram or unknown Ethernet header");
      }
    }
    else break;
  }
  return false;
}


bool DumpReader::getNextIP() {
  free_ptr = false;
  while (true) {
    u_int hlen,version;
    unsigned int len;
    if (this->getNextEthernet()) {
      struct ip_header* ip_ptr;
      ip_ptr = (struct ip_header *) actEthernetData;
      len = ntohs(ip_ptr->ip_len);
      hlen = IP_HL(ip_ptr);
      version = IP_V(ip_ptr);

      /* It must be IPv4 */
      if (version == 4) {
        /* make sure that the packet is at least as long as the min IP header */
        if (actHeader->caplen > sizeof(struct ip_header)) {
        
          /* check and see if we got everything.  NOTE: we must use
           * ip_total_len after this, because we may have captured bytes
           * beyond the end of the packet (e.g. ethernet padding). */
          if (actHeader->caplen >= len) {
            /* IP_sec decoding */
            if(ip_ptr->ip_p == IPPROTO_ESP){
              if((len-hlen*4)>10) {  // minimum size of the ESP 
                unsigned int spi=(((unsigned int)actEthernetData[hlen*4])<<24)+(((unsigned int)actEthernetData[hlen*4+1])<<16)+(((unsigned int)actEthernetData[hlen*4+2])<<8)+actEthernetData[hlen*4+3];
                ESP_obj *espobj;
                if(act_pt->esp.find_esp(spi,espobj)){
                  int icv_len=espobj->icv_fv.invoke(OCTETSTRING(hlen*4,(const unsigned char*)actEthernetData),
                                                 OCTETSTRING(len-hlen*4,(const unsigned char*)actEthernetData+hlen*4),
                                                 espobj->icv_data);
                  if(icv_len>=0){ // valid ICV
                    int proto=*((const unsigned char*)actEthernetData+len-icv_len);
                    OCTETSTRING decrypted_data;
                    if(espobj->decrypt_fv.invoke(OCTETSTRING(hlen*4,(const unsigned char*)actEthernetData),
                                              OCTETSTRING(len-hlen*4-icv_len-1,(const unsigned char*)actEthernetData+hlen*4),
                                              decrypted_data,
                                              espobj->decrypt_data)){ 
                      ip_ptr->ip_p=proto;
                      ip_ptr->ip_len=htons(hlen*4+decrypted_data.lengthof());
                      unsigned char* dataptr=(unsigned char*)actEthernetData+hlen*4;
                      memcpy(actEthernetData+hlen*4,(const unsigned char*)decrypted_data,decrypted_data.lengthof());
                      if(!act_pt->esp.match_esp(&(ip_ptr->ip_src),(dataptr[0]<<8)+dataptr[1],&(ip_ptr->ip_dst),(dataptr[2]<<8)+dataptr[3],espobj)){
                        // The ESP registered for different address
                        PCAPasp__Types::ASP__PCAP__ESP__Report ret_val;
                        ret_val.status__code()=PCAPasp__Types::ESP__Status::ESP__WRONG__SPI;
                        ret_val.spi().set_long_long_val(spi);
                        ret_val.destinationIP()=inet_ntoa(ip_ptr->ip_dst);
                        ret_val.destinationPort()=OMIT_VALUE;
                        ret_val.sourceIP()=inet_ntoa(ip_ptr->ip_src);
                        ret_val.sourcePort()=OMIT_VALUE;
                        ret_val.payload__transport()=-1;
                        act_pt->inc_msg(ret_val);

                      }
                    } else { // decrypt failed
                      PCAPasp__Types::ASP__PCAP__ESP__Report ret_val;
                      ret_val.status__code()=PCAPasp__Types::ESP__Status::ESP__DECRYPT__ERROR;
                      ret_val.spi().set_long_long_val(spi);
                      ret_val.destinationIP()=inet_ntoa(ip_ptr->ip_dst);
                      ret_val.destinationPort()=OMIT_VALUE;
                      ret_val.sourceIP()=inet_ntoa(ip_ptr->ip_src);
                      ret_val.sourcePort()=OMIT_VALUE;
                      ret_val.payload__transport()=-1;
                      act_pt->inc_msg(ret_val);
                    }
                  } else {
                    PCAPasp__Types::ASP__PCAP__ESP__Report ret_val;
                    ret_val.status__code()=PCAPasp__Types::ESP__Status::ESP__ICV__ERROR;
                    ret_val.spi().set_long_long_val(spi);
                    ret_val.destinationIP()=inet_ntoa(ip_ptr->ip_dst);
                    ret_val.destinationPort()=OMIT_VALUE;
                    ret_val.sourceIP()=inet_ntoa(ip_ptr->ip_src);
                    ret_val.sourcePort()=OMIT_VALUE;
                    ret_val.payload__transport()=-1;
                    act_pt->inc_msg(ret_val);
                  }
                } else { // no esp data found
                  PCAPasp__Types::ASP__PCAP__ESP__Report ret_val;
                  ret_val.status__code()=PCAPasp__Types::ESP__Status::ESP__NOT__DEFINED;
                  ret_val.spi().set_long_long_val(spi);
                  ret_val.destinationIP()=inet_ntoa(ip_ptr->ip_dst);
                  ret_val.destinationPort()=OMIT_VALUE;
                  ret_val.sourceIP()=inet_ntoa(ip_ptr->ip_src);
                  ret_val.sourcePort()=OMIT_VALUE;
                  ret_val.payload__transport()=-1;
                  act_pt->inc_msg(ret_val);
                }
              }
            } else {
// Needs more test
/*              unsigned char* dataptr=(unsigned char*)actEthernetData+hlen*4;
              if(act_pt->esp.esp_exists( &(ip_ptr->ip_src),(dataptr[0]<<8)+dataptr[1],&(ip_ptr->ip_dst),(dataptr[2]<<8)+dataptr[3],ip_ptr->ip_p)){
                // ESP data registered for this address
                  PCAPasp__Types::ASP__PCAP__ESP__Report ret_val;
                  ret_val.status__code()=PCAPasp__Types::ESP__Status::NOT__ESP__PACKET;
                  ret_val.spi()=-1;
                  ret_val.destinationIP()=inet_ntoa(ip_ptr->ip_dst);
                  ret_val.destinationPort()=OMIT_VALUE;
                  ret_val.sourceIP()=inet_ntoa(ip_ptr->ip_src);
                  ret_val.sourcePort()=OMIT_VALUE;
                  ret_val.payload__transport()=-1;
                  act_pt->inc_msg(ret_val);
              }*/
            }
          
            if (!(ntohs(ip_ptr->ip_off) & (IP_OFFMASK | IP_MF))) { // no fragmentation
            
              /* We found it! */
              actIPHeader = ip_ptr;
	      actIPData = (u_char*) actEthernetData+(hlen << 2);
              TTCN_warning("whole IP datagramm");
              return true;
            }
            else{
              actIPHeader = ip_ptr;
	      actIPData = (u_char*) actEthernetData+(hlen << 2);
              TTCN_warning("fragfmented IP datagramm");
              if(fragment_buffer.add_ip_fragment(&actIPHeader,&actIPData)){
                free_ptr = true;
              TTCN_warning("last fragfment IP datagramm");
                return true;
              }
            }
          }
          else TTCN_warning("Captured only %d bytes of %d-byte IP datagram", actHeader->caplen, len);
        }
        else TTCN_warning("Received truncated IP datagram!");
      }
      else TTCN_warning("Unknown IP version: %d",version);
    }
    else break;
  }
  return false;
}

TCPSegment* DumpReader::getNextSegment() {
  bool segment_found = false;
  TCPSegment* ret_seg = NULL;
  while (!segment_found) {
    if (getNextIP()) {
      /* we're only looking for TCP or UDP; throw away everything else */
      if (actIPHeader->ip_p == IPPROTO_TCP) {
        segment_found = true;
        actTCPHeader = (struct tcphdr *) actIPData;
        
        // calculate the total length of the TCP header including options
        u_int tcp_header_len = TCP_OFF(actTCPHeader) * 4;
        actTCPData = (u_char*) actTCPHeader + tcp_header_len;
        
        // compute the length of the TCP payload
        u_int ip_total_len = ntohs(actIPHeader->ip_len);
        u_int ip_header_len = IP_HL(actIPHeader) * 4;
        u_int tcp_total_len = ip_total_len - ip_header_len;
        u_int tcp_data_len = tcp_total_len - tcp_header_len;
        
        // we return with the needed information
        ret_seg = new TCPSegment();
        ret_seg->seg_type = TCP_SEG;
        ret_seg->ip_src = actIPHeader->ip_src;
        ret_seg->ip_dst = actIPHeader->ip_dst;
        ret_seg->port_src = ntohs(actTCPHeader->th_sport);
        ret_seg->port_dst = ntohs(actTCPHeader->th_dport);
        ret_seg->seq_num = ntohl(actTCPHeader->th_seq);
        ret_seg->ack_num = ntohl(actTCPHeader->th_ack);
        if (actTCPHeader->th_flags & TH_SYN) ret_seg->syn = true;
        if (actTCPHeader->th_flags & TH_FIN) ret_seg->fin = true;
        ret_seg->put((char*)actTCPData,(size_t)tcp_data_len);
        ret_seg->timestamp = (double)actHeader->ts.tv_sec + (double)actHeader->ts.tv_usec/1000000.0;
        if(free_ptr){
          free_ptr=false;
          Free(actIPHeader);
          Free(actIPData);
        }
        return ret_seg;
      }
      else if (actIPHeader->ip_p == IPPROTO_UDP) {
        segment_found = true;
        actUDPHeader = (struct udphdr *) actIPData;
        actUDPData = ((u_char*) (actUDPHeader))+8;
        
        // compute the length of the UDP payload
        u_int udp_total_len = ntohs(actUDPHeader->uh_ulen);
        u_int udp_data_len = udp_total_len-8;
        
        // we return with the necessery information
        ret_seg = new TCPSegment();
        ret_seg->seg_type = UDP_SEG;
        ret_seg->ip_src = actIPHeader->ip_src;
        ret_seg->ip_dst = actIPHeader->ip_dst;
        ret_seg->port_src = ntohs(actUDPHeader->uh_sport);
        ret_seg->port_dst = ntohs(actUDPHeader->uh_dport);
        ret_seg->put((char*) actUDPData, (size_t) udp_data_len);
        ret_seg->timestamp = (double)actHeader->ts.tv_sec + (double)actHeader->ts.tv_usec/1000000.0;
        if(free_ptr){
          free_ptr=false;
          Free(actIPHeader);
          Free(actIPData);
        }
        return ret_seg;
      }
      else if (actIPHeader->ip_p == IPPROTO_SCTP) {
        segment_found = true;
        actSCTPHeader = (struct sctphdr *) actIPData;
        
        u_int sctp_header_len = 12;
        actSCTPData = (u_char*) actSCTPHeader + sctp_header_len;
        
        // compute the length of the SCTP payload
        u_int ip_total_len = ntohs(actIPHeader->ip_len);
        u_int ip_header_len = IP_HL(actIPHeader) * 4;
        u_int sctp_total_len = ip_total_len - ip_header_len;
        u_int sctp_data_len = sctp_total_len - sctp_header_len;

        ret_seg = new TCPSegment();
        ret_seg->seg_type = SCTP_SEG;
        ret_seg->ip_src = actIPHeader->ip_src;
        ret_seg->ip_dst = actIPHeader->ip_dst;
        ret_seg->port_src = ntohs(actSCTPHeader->sh_sport);
        ret_seg->port_dst = ntohs(actSCTPHeader->sh_dport);
        ret_seg->put((char*) actSCTPData, (size_t) sctp_data_len);
        ret_seg->timestamp = (double)actHeader->ts.tv_sec + (double)actHeader->ts.tv_usec/1000000.0;
        if(free_ptr){
          free_ptr=false;
          Free(actIPHeader);
          Free(actIPData);
        }
        return ret_seg;
      }
    }
    else break;
  }
  return NULL;
}


////////////////////////////////////////////////////////////
// TCPBuffer implementation
////////////////////////////////////////////////////////////
TCPBuffer::TCPBuffer()
{
  length = 0;
  buffer = NULL;
  read_poi = buffer;
  total_length = 0;
  lost_length = 0;
  closed = false;
  close_sent = false;
}

TCPBuffer::~TCPBuffer()
{
  if (buffer) delete [] buffer;
}

void TCPBuffer::clear()
{
  log("cleared");
  length = 0;
  if (buffer) delete [] buffer;
  buffer = NULL; read_poi = buffer;
  closed = false;
  close_sent = false;
}

bool TCPBuffer::ack(TCPSegment* segment)
{
  if (segment != NULL) {
    if (segment->seg_type == TCP_SEG) {
      //If an acknowledgement arrives that is larger than the last 
      //stored byte in the buffer, than a TCP segment must have been lost previously.
      //Because it would prevent the assembly of the stream,
      //we hop the gap - that was created by the lost segment - by clearing the buffer
      //It doesn't contain a valid message, because it would have already been processed then.
      //and setting it to sequence number of the acknowledgement.
      if (segment->ack_num > (seq_num + length+ closed)?1:0) {
        TTCN_warning("Lost TCP segment detected!: Current sequence number: %lu, size: %zu, acknowledgement number: %lu, closed: %s", seq_num, length, segment->ack_num, closed?"true":"false");
        // - The buffer should be cleared.
        // - Saved segments must be dropped if their seq_num is smaller than the ack_num -> this one goes to the Peer class
        clear();
        lost_length+=(segment->ack_num-seq_num-length);
        total_length+=(segment->ack_num-seq_num-length);
        seq_num = segment->ack_num;
        return false;
      }
    }
  }
  return true;
}

void TCPBuffer::log_stat(){
  log("Total processed octets, including lost octets: %lu",total_length);
  log("Total lost octets: %lu",lost_length);
  if(total_length>0){
    log("Quality of the recovered stream: %lu%%",(total_length-lost_length)*100/total_length);
  } else {
    log("Quality of the recovered stream: N/A");
  }
}

bool TCPBuffer::put(TCPSegment* segment)
{
  if (segment != NULL) {
  
    switch (segment->seg_type) {
    
      case TCP_SEG: {
        log("tcp segment is: seq:%lu size:%ld fin:%s\n", seq_num, length, segment->fin?"yes":"no");
        if (segment->fin) {closed=true;}
        if ( (segment->seq_num <= seq_num + length ) && 
             (segment->seq_num >= seq_num) &&
             (segment->length > 0) ) { //The segment can be appended
          size_t old_pos = get_pos();
          size_t new_size = segment->seq_num - seq_num + segment->length;
          unsigned char* tmp_buf = new unsigned char[new_size];
          size_t from_orig_buffer = segment->seq_num - seq_num;
          memcpy(tmp_buf, buffer, from_orig_buffer);
          memcpy( (tmp_buf + from_orig_buffer), segment->payload, segment->length);
          if (buffer) delete [] buffer;
          buffer = tmp_buf;
          length = new_size;
          read_poi = buffer + old_pos;
          timestamp = segment->timestamp;
          total_length+=segment->length;
          if (logging){
          log("tcp segment is appended: seq:%lu size:%ld old_pos:%lu from_orig:%lu\n", seq_num, length, old_pos, from_orig_buffer);
          }
          if (segment) {
            delete segment;
            segment = NULL;
          }
          return true;
        }
        else return false;
      }
      break;

      case UDP_SEG: {
        if (segment->length>0) {
          size_t old_pos = get_pos();
          size_t new_size = length + segment->length;
          char* tmp_buf = new char[new_size];
          memcpy(tmp_buf, buffer, length);
          memcpy(tmp_buf + length, segment->payload, segment->length);
          delete [] buffer;
          buffer = (unsigned char*) tmp_buf;
          length = new_size;
          read_poi = buffer + old_pos;
          timestamp = segment->timestamp;
          if (segment) {
            delete segment;
            segment = NULL;
          }
          if (logging) {
          log("udp segment is appended: seq:%lu size:%ld\n", seq_num, length);
          }
          return true;
        }
        else return false;
      }
      break;
    }
  }
  else return false;
  return false;
}

void TCPBuffer::rewind()
{
  read_poi = buffer;
}

size_t TCPBuffer::get_pos()
{
  return read_poi - buffer;
}

void TCPBuffer::set_pos(size_t pos)
{
  if (pos > length) read_poi = buffer + length;
  else read_poi = buffer + pos;
}

size_t TCPBuffer::get_len()
{
  return length;
}

unsigned char* TCPBuffer::get_data()
{
  return buffer;
}

size_t TCPBuffer::get_read_len()
{
  return length - get_pos();
}

unsigned char* TCPBuffer::get_read_data()
{
  return read_poi;
}

void TCPBuffer::cut()
{
  size_t new_size = get_read_len();
  int seq_offset = get_pos();
  char* tmp_buf = new char[new_size];
  if (new_size) memcpy(tmp_buf, read_poi, new_size);
  delete [] buffer;
  seq_num = seq_num + seq_offset;
  buffer = (unsigned char*) tmp_buf;
  read_poi = buffer;
  length = new_size;
  if (logging) {
    log("buffer is cut: seq:%lu size:%ld\n", seq_num, length);
    dump();
  }
}

void TCPBuffer::cut(size_t cut_bytes) {
  if (cut_bytes > get_len()) cut_bytes = get_len();
  size_t new_size = get_len()-cut_bytes;
  int seq_offset = cut_bytes;
  char* tmp_buf = new char[new_size];
  if (new_size) memcpy(tmp_buf, buffer+cut_bytes, new_size);
  delete [] buffer;
  seq_num = seq_num + seq_offset;
  buffer = (unsigned char*) tmp_buf;
  read_poi = buffer;
  length = new_size;
  if (logging) {
    log("buffer is cut: seq:%lu size:%ld\n", seq_num, length);
    dump();
  }
}

void TCPBuffer::log(const char *fmt, ...) { 
	TTCN_Logger::begin_event(TTCN_DEBUG);
	TTCN_Logger::log_event("TCPBuffer: ");
	va_list ap;
	va_start(ap, fmt);
	TTCN_Logger::log_event_va_list(fmt, ap);
	va_end(ap); 
	TTCN_Logger::end_event(); 
}

void TCPBuffer::dump() {
  TTCN_Logger::begin_event(TTCN_DEBUG);
  TTCN_Logger::log_event("TCPBuffer: seq:%lu size:%d\n", seq_num, (int) length);
  unsigned char* dataptr = buffer;
  for (u_int i=1; i<length+1; i++) {
    TTCN_Logger::log_event("%.2x ", dataptr[i-1]);
    if (i%16==0) TTCN_Logger::log_event("\n");
  }
  TTCN_Logger::log_event("\n");
  TTCN_Logger::end_event();
}


////////////////////////////////////////////////////////////
// Vector implementation
////////////////////////////////////////////////////////////
template < class Type > Vector < Type >::Vector () {
  size = 0;
  actual = 0;
  ar = NULL;
}

template < class Type > Vector < Type >::Vector (Vector < Type > &a) {
  ar = new Type *[size = a.size];
  for (int i = 0; i < a.size; i++)
    ar[i] = a.ar[i];
}

template < class Type > Vector < Type >::~Vector () {
  if (ar)
    delete[]ar;
}

template < class Type > Vector < Type > &Vector < Type >::operator = (Vector < Type > &a) {
  if (this != &a) {
    if (ar)
      delete[]ar;
    ar = new Type *[size = a.size];
    for (int i = 0; i < a.size; i++)
      ar[i] = a.ar[i];
  }
  return *this;
}

template < class Type > Type & Vector < Type >::operator[](int idx) {
  if (idx >= size) {
    Type **nar = new Type *[idx + 1];
    if (ar) {
      for (int i = 0; i < size; i++)
	nar[i] = ar[i];
      for (int j = size; j <= idx; j++)
	nar[j] = NULL;
      delete[]ar;
    }
    size = idx + 1;
    ar = nar;
  }
  actual = idx;
  return *ar[idx];
}

template < class Type > Type * Vector < Type >::elementAt (int idx) {
  actual = idx;
  return &((*this)[idx]);
}

template < class Type > bool Vector < Type >::removeElementAt (int idx) {
  if ((idx < size) && size > 1) {
    Type **nar = new Type *[size - 1];
    if (ar) {
      for (int i = 0; i < idx; i++)
	nar[i] = ar[i];
      for (int j = idx; j < size - 1; j++)
	nar[j] = ar[j + 1];
      delete[]ar;
    }
    size = size - 1;
    ar = nar;
    actual = idx - 1;
    return true;
  }
  else {
    if (idx >= size)
      return false;
    if (size == 1) {
      delete ar;
      ar = NULL;
      size = 0;
      return true;
    }
  }
  return false;
}

template < class Type > bool Vector < Type >::remove (int idx) {
  return removeElementAt (idx);
}

template < class Type > int Vector < Type >::length () {
  return size;
}

template < class Type > void Vector < Type >::append (Type * ptr) {
  Type **nar = new Type *[size + 1];
  if (ar) {
    for (int i = 0; i < size; i++)
      nar[i] = ar[i];
    delete[]ar;
  }
  ar = nar;
  ar[size] = ptr;
  actual = size;
  size++;
}

template < class Type > void Vector < Type >::addElement (Type * ptr) {
  append (ptr);
}

template < class Type > bool Vector < Type >::remove (Type * ptr) {
  for (int i = 0; i < size; i++) {
    if (ar[i] == ptr && ptr != NULL) {
      return removeElementAt (i);
    }
  }
  return false;
}

template < class Type > bool Vector < Type >::removeElement (Type * ptr) {
  return remove (ptr);
}

template < class Type > bool Vector < Type >::removeCurrent () {
  return removeElementAt (actual);
}

template < class Type > bool Vector < Type >::removeRef (Type * ptr) {
  return remove (ptr);
}

template < class Type > int Vector < Type >::find (Type * ptr) {
  for (int i = 0; i < size; i++) {
    if (ar[i] == ptr) {
      actual = i;
      return i;
    }
  }
  return -1;
}

template < class Type > Type * Vector < Type >::first () {
  if (ar) {
    actual = 0;
    return ar[0];
  }
  else
    return NULL;
}

template < class Type > Type * Vector < Type >::last () {
  if (ar) {
    actual = size - 1;
    return ar[size - 1];
  }
  else
    return NULL;
}

template < class Type > Type * Vector < Type >::next () {
  if (ar) {
    actual++;
    if (actual < size)
      return ar[actual];
    else {
      actual = 0;
      return NULL;
    }
  }
  else
    return NULL;
}

template < class Type > Type * Vector < Type >::current () {
  if (ar) {
    if (actual < size) {
      return ar[actual];
    }  else
    return NULL;
  }
  else
    return NULL;
}

template < class Type > Type * Vector < Type >::prev () {
  if (ar) {
    if ((actual > 1) && (actual < size)) {
      actual--;
      return ar[actual];
    }
  }
  else
    return NULL;
}

template < class Type > bool Vector < Type >::isEmpty () {
  if (size == 0){
    return true;}
  return false;
}

template < class Type > void Vector < Type >::destruct () {
  if (ar)
    for (int i = 0; i < size; i++) {
      delete ar[i];
    }
  if (ar) delete[]ar;
  size = 0; actual = 0;
  ar = NULL;
}


////////////////////////////////////////////////////////////
// Peer implementation
////////////////////////////////////////////////////////////
Peer::Peer()
{
  protocol_type = NO_PROTOCOL;
  out_of_sync = true;
  is_sctp = false;
}

Peer::Peer(TCPSegment* segment)
{
  if (segment != NULL) {
    port_src = segment->port_src;
    port_dst = segment->port_dst;
    ip_src = segment->ip_src;
    ip_dst = segment->ip_dst;
    if(segment->seg_type!=SCTP_SEG){
      is_sctp=false;
      if (segment->syn) {
        tcp_buf.seq_num = segment->seq_num + 1;
      }
      else {
        tcp_buf.seq_num = segment->seq_num;
      }
    } else {
//      stream_list.add_segment_to_stream(segment);
      is_sctp= true;
    }
    protocol_type = segment->protocol_type;
    transport_type = segment->seg_type;
    out_of_sync = true;
    log("created");
  }
}

Peer::~Peer()
{
  seg_list.destruct();
}

void Peer::reset()
{
  tcp_buf.clear();
  seg_list.destruct();
  out_of_sync = true;
  log("reset");
}

void Peer::init(TCPSegment* segment)
{
  if (segment != NULL) {
    port_src = segment->port_src;
    port_dst = segment->port_dst;
    ip_src = segment->ip_src;
    ip_dst = segment->ip_dst;
    if(segment->seg_type!=SCTP_SEG){
      is_sctp=false;
      if (segment->syn) {
        tcp_buf.seq_num = segment->seq_num + 1;
      }
      else {
        tcp_buf.seq_num = segment->seq_num;
      }
    } else {
//      stream_list.add_segment_to_stream(segment);
      is_sctp= true;
    }
    protocol_type = segment->protocol_type;
    transport_type = segment->seg_type;
    out_of_sync = true;
    tcp_buf.put(segment);
    log("initialized");
  }
}

bool Peer::compare(TCPSegment* segment)
{
  if (segment != NULL)
    if ( (port_src == segment->port_src) && (port_dst == segment->port_dst) )
      if (memcmp(&ip_src,&(segment->ip_src),sizeof(struct in_addr))==0)
        if (memcmp(&ip_dst,&(segment->ip_dst),sizeof(struct in_addr))==0)
          return true;


  return false;
}

bool Peer::sentBy(TCPSegment* segment)
{
  if (segment != NULL)
    if ( (port_src == segment->port_dst) && (port_dst == segment->port_src) )
      if (memcmp(&ip_src,&(segment->ip_dst),sizeof(struct in_addr))==0)
        if (memcmp(&ip_dst,&(segment->ip_src),sizeof(struct in_addr))==0)
          return true;

  return false;
}

int Peer::get_msg_len(){
  if(is_sctp){
    if(has_message()){
      return get_first_sctp_data_len();
    }
  } else if(!out_of_sync){
    tf__getMsgLen getlen=p_data.get_f_getMsgLen(protocol_type);
    return getlen.invoke(
        OCTETSTRING(tcp_buf.get_read_len(),tcp_buf.get_read_data()),
        tcp_buf.closed,
        transport_type
      );
  }
  return -1;
}

bool Peer::ack(TCPSegment* segment)
{
  if (segment != NULL) {
    //In case the acknowledgment is larger than the last stored byte
    //the tcp_buf.ack clears the buffer and sets the seq_num to the ack_num
    if(!is_sctp){
      if (!tcp_buf.ack(segment)) {
        TCPSegment* seg;

        log("acknowledgement recovering: out of sync");
        out_of_sync = true;
        //First we locate that saved segment which has the smallest seq_num
        TCPSegment* first_saved_segment = NULL;
        int first_saved_segment_idx = 0;

        if (seg_list.length() > 0) {

          for (int i=0; i<seg_list.length(); i++) {
            seg = seg_list.elementAt(i);
            if (first_saved_segment) {
              if (seg->seq_num < first_saved_segment->seq_num) {
                first_saved_segment = seg;
                first_saved_segment_idx = i;
              }
            }
            else {
              first_saved_segment = seg;
              first_saved_segment_idx = i;
            }
          }

          //Then we put it into the buffer:
          if (first_saved_segment) {
            seg_list.removeElementAt(first_saved_segment_idx);
            tcp_buf.seq_num = first_saved_segment->seq_num;
            tcp_buf.put(first_saved_segment);

            //Next we try to put every other saved segments into the buffer
            //if there is any
            if (!seg_list.isEmpty()) {
              log("number of unprocessed segments: %d", seg_list.length());
              //Let's try to put the unprocessed segments into the buffer:
              bool successful_insertion = false;
              do {
                successful_insertion = false;
                TCPSegment* seg = NULL;
                for (int i=0; i<seg_list.length(); i++) {
                  seg = seg_list.elementAt(i);
                  log("Trying to insert: seq_num: %lu, length: %d", seg->seq_num, seg->length);
                  if (tcp_buf.put(seg)) {
                    log("unprocessed segment inserted");
                    successful_insertion = true;
                    //delete seg; seg = NULL;
                    seg_list.removeElementAt(i);
                  }
                  // If we won't be able to put it, we drop it
                  else if (seg->seq_num < tcp_buf.seq_num) {
                    TTCN_warning("Unprocessed segment dropped during ack recovering: IP src: %s, dst: %s; Port src: %d, dst: %d seq: %lu",
                    inet_ntoa(seg->ip_src),
                    inet_ntoa(seg->ip_dst),
                    seg->port_src,
                    seg->port_dst,
                    seg->seq_num
                    );
                    seg_list.removeElementAt(i);
                    delete seg; seg = NULL;
                  }
                }
              }
              while (successful_insertion && seg_list.length());
            }
          }
          tcp_buf.dump();
          log("out_of_sync: %d",out_of_sync);
          log("protocol_type: %d",protocol_type);
          if (out_of_sync ) {
            out_of_sync = !tryToResync();
            log("out_of_sync: %d",out_of_sync);
            tcp_buf.dump();
          }
        }
        else {
          tcp_buf.seq_num = segment->ack_num;
          TCPSegment* seg = NULL;
          for (int i=0; i<seg_list.length(); i++) {
            seg = seg_list.elementAt(i);
            if (seg->seq_num < tcp_buf.seq_num) {
              TTCN_warning("Unprocessed segment dropped during ack recovering: IP src: %s, dst: %s; Port src: %d, dst: %d seq: %lu",
              inet_ntoa(seg->ip_src),
              inet_ntoa(seg->ip_dst),
              seg->port_src,
              seg->port_dst,
              seg->seq_num
              );
              seg_list.removeElementAt(i);
              delete seg; seg = NULL;
            }
          }
        }
        return false;
      }
    } else {
      stream_list.ack(segment);
    }
  }
  return true;
}

void Peer::put(TCPSegment* segment)
{
  if (segment != NULL) {
    if (compare(segment) && ((segment->length > 0) || segment->fin)) {
      if(is_sctp){
        stream_list.add_segment_to_stream(segment);
        delete segment;
        segment = NULL;
      } else {
        if (tcp_buf.put(segment)) {
          log("segment inserted");
          if (!seg_list.isEmpty()) {
            log("number of unprocessed segments: %d", seg_list.length());
            //Let's try to put the unprocessed segments into the buffer:
            bool successful_insertion = false;
            do {
              successful_insertion = false;
              TCPSegment* seg = NULL;
              for (int i=0; i<seg_list.length(); i++) {
                seg = seg_list.elementAt(i);
                log("Trying to insert: seq_num: %lu, length: %d", seg->seq_num, seg->length);
                if (tcp_buf.put(seg)) {
                  log("unprocessed segment inserted");
                  successful_insertion = true;
                  seg_list.removeElementAt(i);
                }
                // If we won't be able to put it, we drop it
                else if (seg->seq_num < tcp_buf.seq_num) {
                  TTCN_warning("Unprocessed TCP segment is dropped: IP src: %s, dst: %s; Port src: %d, dst: %d seq: %lu",
                    inet_ntoa(seg->ip_src),
                    inet_ntoa(seg->ip_dst),
                    seg->port_src,
                    seg->port_dst,
                    seg->seq_num
                  );
                  seg_list.removeElementAt(i);
                  delete seg; seg = NULL;
                }
              }
            }
            while (successful_insertion && seg_list.length());
          }
          tcp_buf.dump();
          log("out_of_sync: %d",out_of_sync);
          log("protocol_type: %d",protocol_type);
          if (out_of_sync ) {
            out_of_sync = !tryToResync();
            log("out_of_sync: %d",out_of_sync);
            tcp_buf.dump();
          }
        }
        else {
          if (segment->seq_num < tcp_buf.seq_num) {
            TTCN_warning("TCP segment is dropped: IP src: %s, dst: %s; Port src: %d, dst: %d seq: %lu",
              inet_ntoa(segment->ip_src),
              inet_ntoa(segment->ip_dst),
              segment->port_src,
              segment->port_dst,
              segment->seq_num
            );
            delete segment; segment = NULL;
          }
          else if (segment->length > 0) {
            log("segment saved as unprocessed");
            seg_list.addElement(segment);
          } else {delete segment; segment = NULL;}
        }
      } // is_sctp
    } else {delete segment; segment = NULL;} // end of if (compare(segment) && (segment->length > 0))
  } // end of if (segment != NULL)
}



bool Peer::tryToResync()
{
  log("trying to resync");
  bool found = false;
  if (tcp_buf.get_read_len()>0) {
    tf__getMsgStartPos getstartpos=p_data.get_f_getMsgStartPos(protocol_type);
    int startpos=getstartpos.invoke(
        OCTETSTRING(tcp_buf.get_read_len(),tcp_buf.get_read_data()),
        tcp_buf.closed,
        transport_type
      );
    if(startpos>=0){
      found=true;
      tcp_buf.set_pos(tcp_buf.get_pos()+startpos);
      log("syncronized, Protocol: %d, position %d",protocol_type,startpos);
    } else {
      log("not syncronized, Protocol: %d, position %d",protocol_type,startpos);
    }
  }
  return found;
}

bool Peer::has_message(){
  return stream_list.has_message();
}
unsigned char* Peer::get_first_sctp_data(){
  return stream_list.get_first_sctp_data();
}
size_t Peer::get_first_sctp_data_len(){
  return stream_list.get_first_sctp_data_len();
}
double Peer::get_first_sctp_timestamp(){
  return stream_list.get_first_sctp_timestamp();
}
void Peer::delete_first_sctp_message(){
  return stream_list.delete_first_sctp_message();
}

void Peer::log_stat(){
  log("Connection statistic:");
  if(is_sctp){
    stream_list.log_stat();
  } else {
    tcp_buf.log_stat();
  }
}


void Peer::dump() {
  if(is_sctp){
    stream_list.dump();
  } else {
    log("prot_type: %d, seg_list_length: %d", protocol_type, seg_list.length());
    tcp_buf.dump();
  }
}

void Peer::log(const char *fmt, ...) {
  if (logging) {
    TTCN_Logger::begin_event(TTCN_DEBUG);
    TTCN_Logger::log_event("Peer (%d->%d): ", port_src, port_dst);
    va_list ap;
    va_start(ap, fmt);
    TTCN_Logger::log_event_va_list(fmt, ap);
    va_end(ap); 
    TTCN_Logger::end_event();
  }
}


////////////////////////////////////////////////////////////
// PeerList implementation
////////////////////////////////////////////////////////////
PeerList::PeerList()
{
  tcp = true;
}

PeerList::~PeerList()
{
  peer_list.destruct();
}

bool PeerList::sendSegmentToPeer(TCPSegment* segment)
{
  bool ret = true;
  if (segment!=NULL) {
    //If it is a TCP segment, we examine if the acknowledgement
    //number of the segment in order to detect lost segments
    if (segment->seg_type == TCP_SEG || segment->seg_type == SCTP_SEG) {
      Peer* other_peer;
      other_peer = getOtherPeer(segment);
      if (other_peer)
        if (!other_peer->ack(segment))
          ret = false;
    }
      
    //Sending the segment to the destination peer
    Peer* act_peer;
    act_peer = getPeer(segment);
    if (act_peer) {
      if (segment->syn) {
        // We have detected this stream already, and now it is
        // re-initialized
        log("sendSegmentToPeer: re-initialization");
        act_peer->reset();
        act_peer->init(segment);
      }
      else {
        // We have already detected this stream and now we send it
        // the actual segment
        log("sendSegmentToPeer: sending to corresponding peer");
        act_peer->put(segment);
      }
    }
    else {
      // We haven't detected this stream yet, therefore we must create the 
      // Peer object that will handle this.
      log("sendSegmentToPeer: creating new stream");
      addPeer(segment);
    }
  }
  return ret; // return false if there is an acknoledgement mismatch
}

void PeerList::addPeer(TCPSegment* segment)
{
  Peer* new_peer;
  new_peer = new Peer(segment);
  peer_list.addElement(new_peer);
  new_peer->put(segment);
}

Peer* PeerList::getPeer(TCPSegment* segment)
{
  Peer* peer_poi = NULL;
  for (int i=0; i<peer_list.length(); i++) {
    peer_poi = peer_list.elementAt(i);
    if (peer_poi->compare(segment)) return peer_poi;
  }
  return NULL;
}

void PeerList::log_stat(){
  Peer* peer_poi = NULL;
  for (int i=0; i<peer_list.length(); i++) {
    peer_poi = peer_list.elementAt(i);
    peer_poi->log_stat();
  }
}


Peer* PeerList::getOtherPeer(TCPSegment* segment)
{
  Peer* peer_poi = NULL;
  for (int i=0; i<peer_list.length(); i++) {
    peer_poi = peer_list.elementAt(i);
    if (peer_poi->sentBy(segment)) return peer_poi;
  }
  return NULL;
}

void PeerList::setType(bool t) {
  tcp = t;
}

Peer* PeerList::elementAt(int i) {
  return peer_list.elementAt(i);
}

int PeerList::length() {
  return peer_list.size;
}

void PeerList::dump() {
  log("#of peers: %d",peer_list.size);
  Peer* peer_poi;
  for (int i=0; i<peer_list.length(); i++) {
    peer_poi = peer_list.elementAt(i);
    peer_poi->dump();
  }
}

void PeerList::log(const char *fmt, ...) {
  
  if (logging) {
    TTCN_Logger::begin_event(TTCN_DEBUG);
    TTCN_Logger::log_event("PeerList (");
    if (tcp)
      TTCN_Logger::log_event("TCP");
    else
      TTCN_Logger::log_event("UDP or SCTP");
    TTCN_Logger::log_event("): ");
    va_list ap;
    va_start(ap, fmt);
    TTCN_Logger::log_event_va_list(fmt, ap);
    va_end(ap); 
    TTCN_Logger::end_event();
  }
}


////////////////////////////////////////////////////////////
// FilterEntry implementation
////////////////////////////////////////////////////////////
FilterEntry::FilterEntry(int protocol, struct in_addr sip, bool sip_all, struct in_addr dip, unsigned int rport)
{
  protocol_type = protocol;
  ip_src = sip;
  ip_src_all = sip_all;
  ip_dst = dip;
  port_dst = rport;
}

FilterEntry::~FilterEntry() {
}

bool FilterEntry::compare(TCPSegment* seg) {
  if (seg != NULL) {
    if ( (port_dst == seg->port_dst) )
    {
      if (ip_src_all)
        if (memcmp(&ip_dst,&(seg->ip_dst),sizeof(struct in_addr))==0)
          return true;
        else return false;
      else if (memcmp(&ip_src,&(seg->ip_src),sizeof(struct in_addr))==0)
        if (memcmp(&ip_dst,&(seg->ip_dst),sizeof(struct in_addr))==0)
          return true;
        else return false;
      else return false;
    }
    else if ( (port_dst == seg->port_src) )
    {
      if (ip_src_all)
        if (memcmp(&ip_dst,&(seg->ip_src),sizeof(struct in_addr))==0)
          return true;
        else return false;
      else if (memcmp(&ip_src,&(seg->ip_dst),sizeof(struct in_addr))==0)
        if (memcmp(&ip_dst,&(seg->ip_src),sizeof(struct in_addr))==0)
          return true;
        else return false;
      else return false;
    }
    else return false;
  }
  else return false;
}

void FilterEntry::log(const char *fmt, ...) { 
  TTCN_Logger::begin_event(TTCN_DEBUG);
  TTCN_Logger::log_event("FilterEntry: ");
  va_list ap;
  va_start(ap, fmt);
  TTCN_Logger::log_event_va_list(fmt, ap);
  va_end(ap); 
  TTCN_Logger::end_event();
}


////////////////////////////////////////////////////////////
// FilterTable implementation
////////////////////////////////////////////////////////////
FilterTable::FilterTable() {}

FilterTable::~FilterTable()
{
  entry_list.destruct();
}

void FilterTable::addEntry(int protocol, struct in_addr sip, bool sip_all, struct in_addr dip, unsigned int rport)
{
  FilterEntry* new_entry;
  new_entry = new FilterEntry(protocol, sip, sip_all, dip, rport);
  entry_list.addElement(new_entry);
  log("adding prot: %d, rPort:%d, sIP:%s", protocol, rport, inet_ntoa(sip));
  log(" dIP:%s", inet_ntoa(dip));
}

int FilterTable::filter(TCPSegment* segment)
{
  if (segment) {
    if (noFilter) return 1;
    FilterEntry* entry_poi = NULL;
    for (int i=0; i<entry_list.length(); i++) {
      entry_poi = entry_list.elementAt(i);
      if (entry_poi->compare(segment)) return entry_poi->protocol_type;
    }
  }
  return NO_PROTOCOL;
}

void FilterTable::log(const char *fmt, ...) {
  if (logging) {
    TTCN_Logger::begin_event(TTCN_DEBUG);
    TTCN_Logger::log_event("FilterTable: ");
    va_list ap;
    va_start(ap, fmt);
    TTCN_Logger::log_event_va_list(fmt, ap);
    va_end(ap); 
    TTCN_Logger::end_event();
  }
}


////////////////////////////////////////////////////////////
// Fragment implementation
////////////////////////////////////////////////////////////
IP_fragment::IP_fragment(){
  id=0;
  buffer=NULL;
  header=NULL;
  buffer_len=0;
  data_len=0;
}

IP_fragment::~IP_fragment(){
  if(buffer) Free(buffer);
  if(header) Free(header);
  holes.destruct();
}

void IP_fragment::clear(){
  if(buffer) Free(buffer);
  if(header) Free(header);
  id=0;
  buffer=NULL;
  header=NULL;
  buffer_len=0;
  data_len=0;
  holes.destruct();
}

bool IP_fragment::add_fragment(struct ip_header* IPHeader,
                             u_char* IPData){
  Holes_list new_holes;
  u_int16_t fr_first=(ntohs(IPHeader->ip_off) & IP_OFFMASK)<<3;
  u_int16_t fr_len=ntohs(IPHeader->ip_len)-(IP_HL(IPHeader)<<2);
  u_int16_t fr_last=fr_first+fr_len-1;
               
  if(holes.isEmpty()){ // first arrived fragment
   id=IPHeader->ip_id;
    Hole* new_hole=new Hole(0,c_infinite);
    holes.append(new_hole);
  }
  if(buffer_len<fr_last){
    buffer=(u_char*)Realloc(buffer,(fr_last+1)*sizeof(u_char));
    buffer_len=fr_last+1;
  }
  memcpy(buffer+fr_first,IPData,fr_len);

  if(!fr_first){ // first fragment, store header
    header=(ip_header*)Malloc(sizeof(ip_header));
    memcpy(header,IPHeader,sizeof(ip_header));
  }
  
  Hole* hole_ptr=holes.first();
  while(hole_ptr){
    if(fr_first<=hole_ptr->last && fr_last>=hole_ptr->first){
      holes.removeCurrent();
      if(fr_first>hole_ptr->first){
        Hole* new_hole=new Hole(hole_ptr->first,fr_first-1);
        new_holes.append(new_hole);
      }
      if(fr_last<hole_ptr->last && (ntohs(IPHeader->ip_off) & IP_MF)){
        Hole* new_hole=new Hole(fr_last+1,hole_ptr->last);
        new_holes.append(new_hole);
      }
      delete hole_ptr;
    }
    hole_ptr=holes.next();
  }
  if(!new_holes.isEmpty ()){
    for(int a=0;a<new_holes.length();a++) holes.append(&new_holes[a]);
  }
  
  return holes.isEmpty ();
}


bool IP_fragment::get_fragment(struct ip_header** IPHeader,
                             u_char** IPData){
  if(header){
    *IPHeader=(ip_header*)Malloc(sizeof(ip_header));
    memcpy(*IPHeader,header,sizeof(ip_header));
  } 
  if(buffer_len){
    (*IPHeader)->ip_len=htons(buffer_len+(IP_HL(*IPHeader)<<2));
    *IPData=(u_char*)Malloc(buffer_len*sizeof(u_char));
    memcpy(*IPData,buffer,buffer_len*sizeof(u_char));
  }
  return header && holes.isEmpty();
}

IP_fragments::IP_fragments(){
}

IP_fragments::~IP_fragments(){
 clear();
}

void IP_fragments::clear(){
  packet_list.destruct();
}

bool IP_fragments::check(){
  return !packet_list.isEmpty();
}

bool IP_fragments::add_ip_fragment(struct ip_header** IPHeader,
                             u_char** IPData){
  int packed_id;
  for(packed_id=0;packed_id<packet_list.length();packed_id++){
    if(packet_list[packed_id].id==(*IPHeader)->ip_id) break;
  }

  if(packed_id==packet_list.length()){
    IP_fragment* new_fr=new IP_fragment;
    packet_list.append(new_fr);
  }

  if(packet_list[packed_id].add_fragment(*IPHeader,*IPData)){
    packet_list[packed_id].get_fragment(IPHeader,IPData);
    IP_fragment* fr= &packet_list[packed_id];
    packet_list.removeElementAt(packed_id);
    delete fr;
    return true;
  }
  return false;

}

void decode_sctp(TCPSegment* segment, SCTP_chunk_list& list){

  unsigned char* payload=segment->payload;
  int length=segment->length;
  int type;
  unsigned char flags;
  int idx=0;
  size_t chunk_length;
  while(length>0){
    type=payload[0];
    flags=payload[1];
    chunk_length=((size_t)(payload[2])<<8)+payload[3];
    switch(type){
      case 0: // Data
genlog("Data segment");
        list.append(new SCTP_chunk);
        list.current()->type=type;
genlog("Data segment flags %Xd",flags);
        list.current()->flags=flags;
        list.current()->length=chunk_length;
        list.current()->data.data.tsn=(payload[4]<<24)+(payload[5]<<16)+(payload[6]<<8)+payload[7];
genlog("Data segment tsn %Xd",list.current()->data.data.tsn);
        list.current()->data.data.sid=(payload[8]<<8)+payload[9];
genlog("Data segment sid %Xd",list.current()->data.data.sid);
        list.current()->data.data.ssn=(payload[10]<<8)+payload[11];
genlog("Data segment ssn %Xd",list.current()->data.data.ssn);
        list.current()->data.data.ppid=(payload[12]<<24)+(payload[13]<<16)+(payload[14]<<8)+payload[15];
genlog("Data segment ppid %Xd",list.current()->data.data.ppid);
        list.current()->data.data.begin=(flags&0x02);
genlog("Data segment begin %Xd",list.current()->data.data.begin);
        list.current()->data.data.end=(flags&0x01);
genlog("Data segment end %Xd",list.current()->data.data.end);
        list.current()->data.data.length=chunk_length-16;
genlog("Data segment length %d",list.current()->data.data.length);
        list.current()->data.data.data=payload+16;
        idx++;
        break;
      case 3: // SACK
        list.append(new SCTP_chunk);
        list.current()->type=type;
        list.current()->flags=flags;
        list.current()->length=chunk_length;
        list.current()->data.ack_tsn=(payload[4]<<24)+(payload[5]<<16)+(payload[6]<<8)+payload[7];
        idx++;
        break;
      default:
        break;
    }
    chunk_length=((chunk_length+3)/4)*4;
    length-=chunk_length;
    payload+=chunk_length;
  }
}

SCTP_Stream_list::SCTP_Stream_list(){
acked_tsn=0;
}

SCTP_Stream_list::~SCTP_Stream_list(){
  streams.destruct();
}

void SCTP_Stream_list::add_segment_to_stream(TCPSegment* segment){
genlog("SCTP_Stream_list::add_segment_to_stream");
  SCTP_chunk_list chunk_list;
  decode_sctp(segment, chunk_list);
  for(int i=0;i<chunk_list.length();i++){
    if(chunk_list[i].type==0){ // SCTP data chunk
genlog("SCTP_Stream_list::add_segment_to_stream SCTP data chunk");
      if(acked_tsn<chunk_list[i].data.data.tsn){
        if(!add_to_stream(chunk_list[i].data.data, segment->timestamp)){
          add_stream(chunk_list[i].data.data,segment->timestamp);
        }
      }
    }
  }
  chunk_list.destruct();
genlog("SCTP_Stream_list::add_segment_to_stream end");
}

void SCTP_Stream_list::ack(TCPSegment* segment){
genlog("SCTP_Stream_list::ack");
  SCTP_chunk_list chunk_list;
  decode_sctp(segment, chunk_list);
  for(int i=0;i<chunk_list.length();i++){
    if(chunk_list[i].type==3){
      if(acked_tsn<chunk_list[i].data.ack_tsn){
        acked_tsn=chunk_list[i].data.ack_tsn;
        for(int k=0;k<streams.length();k++){
          streams[k].ack_message(chunk_list[i].data.ack_tsn);
        }
      }
    }
  }
  chunk_list.destruct();
genlog("SCTP_Stream_list::ack end");
}


bool SCTP_Stream_list::add_to_stream(SCTP_data_chunk &data, double timestamp){
genlog("SCTP_Stream_list::add_to_stream");
  for(int i=0;i<streams.length();i++){
    if(streams[i].stream_id==data.sid){
      streams[i].add_segment(data,timestamp);
genlog("SCTP_Stream_list::add_to_stream true");
      return true;
     }
  }
genlog("SCTP_Stream_list::add_to_stream false");
  return false;
}

bool SCTP_Stream_list::has_message(){
genlog("SCTP_Stream_list::has_message");
  for(int i=0;i<streams.length();i++){
    if(streams[i].has_message()){
genlog("SCTP_Stream_list::has_message true");
      return true;
    }
  }
genlog("SCTP_Stream_list::has_message false");
  return false;
}

unsigned char* SCTP_Stream_list::get_first_sctp_data(){
  int idx=0;
  double timestamp=-1.0;
  for(int i=0;i<streams.length();i++){
    if(streams[i].has_message() && (timestamp==-1.0 || timestamp>streams[i].get_first_ts())){
      timestamp=streams[i].get_first_ts();
      idx=i;
    }
  }
  return streams[idx].get_first_message_data();
}

size_t SCTP_Stream_list::get_first_sctp_data_len(){
  int idx=0;
  double timestamp=-1.0;
  for(int i=0;i<streams.length();i++){
    if(streams[i].has_message() && (timestamp==-1.0 || timestamp>streams[i].get_first_ts())){
      timestamp=streams[i].get_first_ts();
      idx=i;
    }
  }
  return streams[idx].get_first_message_data_len();
}


double SCTP_Stream_list::get_first_sctp_timestamp(){
//  int idx=0;
  double timestamp=-1.0;
  for(int i=0;i<streams.length();i++){
    if(streams[i].has_message() && (timestamp==-1.0 || timestamp>streams[i].get_first_ts())){
      timestamp=streams[i].get_first_ts();
//      idx=i;
    }
  }
  return timestamp;
}

void SCTP_Stream_list::delete_first_sctp_message(){
  int idx=0;
  double timestamp=-1.0;
  for(int i=0;i<streams.length();i++){
    if(streams[i].has_message() && (timestamp==-1.0 || timestamp>streams[i].get_first_ts())){
      timestamp=streams[i].get_first_ts();
      idx=i;
    }
  }
  streams[idx].delete_first_message();
}

void SCTP_Stream_list::add_stream(SCTP_data_chunk &data, double timestamp){
  SCTP_stream *new_stream= new SCTP_stream;
  streams.append(new_stream);
  new_stream->add_segment(data,timestamp);
}


void SCTP_Stream_list::log_stat(){
}

void SCTP_Stream_list::dump(){
}

SCTP_stream::SCTP_stream(){
  stream_id=0;


}

SCTP_stream::~SCTP_stream(){
  message_list.destruct();
}

void SCTP_stream::add_segment(SCTP_data_chunk &data, double timestamp){
genlog("SCTP_stream::add_segment");  
  int data_idx=get_idx(data.ssn);
  SCTP_message *message;
  if(data_idx==-1){
    message=new SCTP_message;
    message_list.addElement(message);
  } else {
    message=message_list.elementAt(data_idx);
  }
  stream_id=data.sid;
  message->add_segment(data,timestamp);
genlog("SCTP_stream::add_segment end");  
}

bool SCTP_stream::has_message(){
  int data_idx=find_first_message();
  if(data_idx!=-1) return message_list[data_idx].complete;
  return false;
}

double SCTP_stream::get_first_ts(){
  int data_idx=find_first_message();
  if(data_idx!=-1) return message_list[data_idx].timestamp;
  return 0.0;
}

unsigned char*  SCTP_stream::get_first_message_data(){
  int data_idx=find_first_message();
  if(data_idx!=-1) return message_list[data_idx].data;
  return NULL;
}

size_t  SCTP_stream::get_first_message_data_len(){
  int data_idx=find_first_message();
  if(data_idx!=-1) return message_list[data_idx].length;
  return 0;
}

int SCTP_stream::find_first_message(){
  unsigned int ssn=0;
  int idx=-1;
  for(int i=0;i<message_list.length();i++){
    if(idx==-1 || ssn>message_list[i].ssn){
      ssn=message_list[i].ssn;
      idx=i;
    }
  }
  return idx;
}

void SCTP_stream::delete_first_message(){
  int data_idx=find_first_message();
  if(data_idx!=-1) {
    delete message_list.elementAt(data_idx);
    message_list.remove(data_idx);
  }
}

void SCTP_stream::ack_message(unsigned int ack_tsn){
  SCTP_message *message=message_list.first();
  while(message){
    if(!message->complete && (message->last_cons_tsn<ack_tsn)){
      delete message;
      message_list.removeCurrent();
    }
    message=message_list.next();
  }
}

int SCTP_stream::get_idx(unsigned int ssn){
genlog("SCTP_stream::get_idx");  

  for(int i=0;i<message_list.length();i++){
    if(ssn==message_list[i].ssn){
genlog("SCTP_stream::get_idx ret: %d",i);  
      return i;
    }
  }
genlog("SCTP_stream::get_idx ret -1");  
  return -1;
}

SCTP_message::SCTP_message(){
  complete=false;
  first_rcvd=false;
  last_rcvd=false;
  ssn=0;

  last_cons_tsn=0;
  ppid=0;
  fragments=NULL;
  length=0;
  data=NULL;
  timestamp=0.0;
}

SCTP_message::~SCTP_message(){
  free_segments();
  Free(data);
}

void SCTP_message::add_segment(SCTP_data_chunk &chunk, double time_stamp){
  if(complete) return;
  if(fragments==NULL){ // first received segment
    if(chunk.begin && chunk.end){ // complete
      complete=true;
      first_rcvd=true;
      last_rcvd=true;
      ssn=chunk.ssn;
      ppid=chunk.ppid;
      first_tsn=chunk.tsn;
      last_tsn=chunk.tsn;
      last_cons_tsn=chunk.tsn;
      length=chunk.length;
      timestamp=time_stamp;
      data= (unsigned char*)Malloc(length*sizeof(unsigned char));
      memcpy(data,chunk.data,length);
      return;
    } else {
      ssn=chunk.ssn;
      ppid=chunk.ppid;
      fragments=new SCTP_data_fragment_list;
    }
  } 
  if(chunk.begin){
    first_rcvd=true;
    first_tsn=chunk.tsn;
  }
  if(chunk.end){
    last_rcvd=true;
    last_tsn=chunk.tsn;
  }
  if(get_idx(chunk.tsn)==-1){
    SCTP_data_fragment *fragment=new SCTP_data_fragment(chunk);
    fragments->addElement(fragment);
  }
  if(first_rcvd && last_cons_tsn<chunk.tsn){
    if(last_cons_tsn==0) last_cons_tsn=first_tsn;
    while(get_idx(last_cons_tsn+1)!=-1){
      last_cons_tsn++;
    }
  }
  if(first_rcvd && last_rcvd && last_cons_tsn==last_tsn){
    size_t curr_length=0;
    for(unsigned int curr_tsn=first_tsn;curr_tsn<=last_tsn;curr_tsn++){
      int idx=get_idx(curr_tsn);
      data= (unsigned char*)Realloc(data,(curr_length+fragments->elementAt(idx)->length)*sizeof(unsigned char));
      memcpy(data+curr_length,fragments->elementAt(idx)->data,fragments->elementAt(idx)->length);
      curr_length+=fragments->elementAt(idx)->length;
    }
    length=curr_length;
    complete=true;
    timestamp=time_stamp;
    free_segments();
  }
}

void SCTP_message::free_segments(){
  if(fragments){
    fragments->destruct();
    delete fragments;
    fragments=NULL;
  }
}

int SCTP_message::get_idx(unsigned int tsn){
  if(fragments){
    for(int i=0;i<fragments->length();i++){
      if(fragments->elementAt(i)->tsn==tsn) return i;
    }
  }
  return -1;
}

SCTP_data_fragment::SCTP_data_fragment(SCTP_data_chunk &chunk){
  begin=chunk.begin;
  end=chunk.end;
  tsn=chunk.tsn;
  length=chunk.length;
      data= (unsigned char*)Malloc(length*sizeof(unsigned char));
      memcpy(data,chunk.data,length);
}

SCTP_data_fragment::~SCTP_data_fragment(){
Free(data);
}

Protocol_data::Protocol_data(){
}

Protocol_data::~Protocol_data(){
  data_list.destruct();
}

void Protocol_data::add_protocol(const int id, const tf__getMsgLen& f_getMsgLen, const tf__getMsgStartPos& f_getMsgStartPos){
  int idx=get_idx(id);
  protocol_def *def;
  if(idx==-1){
    def=new protocol_def;
    data_list.append(def);
  } else {
    def=data_list.elementAt(idx);
  }
  def->id=id;
  def->f_getMsgLen=f_getMsgLen;
  def->f_getMsgStartPos=f_getMsgStartPos;
}

int Protocol_data::get_idx(int id){
  protocol_def *def;
  for(int i=0; i<data_list.length();i++){
    def=data_list.elementAt(i);
    if(def->id==id) return i;
  }
  
  return -1;
}

const tf__getMsgLen& Protocol_data::get_f_getMsgLen(int id){
  int idx=get_idx(id);
  if(idx==-1) return def_getMsgLen_ref;
  protocol_def *def=data_list.elementAt(idx);
  return def->f_getMsgLen;
}

const tf__getMsgStartPos& Protocol_data::get_f_getMsgStartPos(int id){
  int idx=get_idx(id);
  if(idx==-1) return def_getMsgStartPos_ref;
  protocol_def *def=data_list.elementAt(idx);
  return def->f_getMsgStartPos;
}

}// namespace
