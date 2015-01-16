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
//  File:		PCAPasp_PT.hh
//  Description:	PCAP port header
//  Rev:                R7A
//  Prodnr:             CNL 113 443

#ifndef PCAPasp_PT_HH
#define PCAPasp_PT_HH

#include "PCAPasp_PortType.hh"

#include <pcap.h>
#include <netinet/in.h>
#include <list>
#include <string>
#include <map>

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif



////////////////////////////////////////////////////////////
// TCPSegment class
////////////////////////////////////////////////////////////

#define TCP_SEG 0
#define UDP_SEG 1
#define SCTP_SEG 2

#define NO_PROTOCOL 0
#define DIAMETER_PROTOCOL 1
#define LDAP_PROTOCOL 2
#define RADIUS_PROTOCOL 3
#define SIP_PROTOCOL 4

#define PCAP_ETHERTYPE_VLAN8021Q 0x8100
struct ether_header;
class SCTP_Stream_list;

namespace PCAPasp__PortType{
class TCPSegment {

  public:
    //Stream identifiers:
    unsigned int port_src;
    unsigned int port_dst;
    struct in_addr ip_src;
    struct in_addr ip_dst;

    int seg_type;       // Can be TCP_SEG or UDP_SEG or SCTP_SEG
    bool syn;           // True if it's a SYN TCP segment
    bool fin;           // True it it's a FIN TCP segment
    unsigned long int seq_num;     // Sequence number for TCP_SEG
    unsigned long int ack_num;     // Acknowledgement number for TCP_SEG
    
    unsigned char* payload;     // Payload buffer for TCP and UDP
    size_t length;     // Length of the payload buffer
    
    double timestamp;
    int protocol_type;  // DIA,LDAP,RADIUS, NONE    
    
  public:
    TCPSegment();
    ~TCPSegment();
    void put(char* buf, size_t size);
    void log(const char *fmt, ...);
    void log();
};

class ESP_obj{
  public:
  ESP_obj(PCAPasp__Types::ASP__PCAP__ESP__Setup);
  ~ESP_obj();
  unsigned int spi;
  int mode; // 1-transport, 2-tunnel
  std::string ip_port;  // concatenation of src_ip, dst_ip, src_port,dst_port
                        // converted to octet strem in netwotk byte order
                        // If any of them are not specified, represented as 0
  PCAPasp__Types::tf__ICV__check  icv_fv;
  OCTETSTRING icv_data;
  PCAPasp__Types::tf__ESP__decrypt  decrypt_fv;
  OCTETSTRING decrypt_data;
};

class ESP_handler{
  public:
   ESP_handler();
   ~ ESP_handler();
   
   std::list<ESP_obj*> ESP_OBJ_list;
   std::map<unsigned int, ESP_obj*>  spi_ESP_obj_map;
   std::map<std::string, ESP_obj*> address_ESP_obj_map;
   
   bool setup_esp(PCAPasp__Types::ASP__PCAP__ESP__Setup);  // add or delete ESP
   void clean_up();
   // Finds the ESP object for the spi
   bool find_esp(unsigned int spi, ESP_obj *& esp);


   // Retrun true if there is a registered SPI for the addresses
   bool esp_exists(struct in_addr *ip_src, unsigned int port_src,struct in_addr *ip_dst,unsigned int port_dst,unsigned int proto);

   bool match_esp(struct in_addr *ip_src, unsigned int port_src,struct in_addr *ip_dst,unsigned int port_dst,const ESP_obj *esp);
};

////////////////////////////////////////////////////////////
// DumpReader class
////////////////////////////////////////////////////////////

#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif

#ifndef u_int8_t
#define u_int8_t uint8_t
#endif
#ifndef u_int16_t
#define u_int16_t uint16_t
#endif
#ifndef u_int32_t
#define u_int32_t uint32_t
#endif

struct vlan_header {
        u_int16_t       vlan_head;
        u_int16_t       vlan_type;
};

struct ip_header {
	u_int8_t	ip_vhl;		/* header length, version */
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
	u_int8_t	ip_tos;		/* type of service */
	u_int16_t	ip_len;		/* total length */
	u_int16_t	ip_id;		/* identification */
	u_int16_t	ip_off;		/* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
	u_int8_t	ip_ttl;		/* time to live */
	u_int8_t	ip_p;		/* protocol */
	u_int16_t	ip_sum;		/* checksum */
	struct in_addr  ip_src;
        struct in_addr  ip_dst;	        /* source and dest address */
};

/*
 * TCP header.
 * Per RFC 793, September, 1981.
 */
struct tcphdr {
 u_int16_t	th_sport;		/* source port */
 u_int16_t	th_dport;		/* destination port */
 u_int32_t	th_seq;			/* sequence number */
 u_int32_t	th_ack;			/* acknowledgement number */
 u_int8_t       th_off;                 /* data offset + reserved */
 #define TCP_OFF(tcp)	(((tcp)->th_off & 0xf0) >> 4)

 u_char	th_flags;
 #define	TH_FIN	0x01
 #define	TH_SYN	0x02
 #define	TH_RST	0x04
 #define	TH_PUSH	0x08
 #define	TH_ACK	0x10
 #define	TH_URG	0x20
 #define	TH_ECE	0x40
 #define	TH_CWR	0x80
 #define	TH_FLAGS	(TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
		    
 u_int16_t	th_win;			/* window */
 u_int16_t	th_sum;			/* checksum */
 u_int16_t	th_urp;			/* urgent pointer */
};

struct udphdr {
 u_short uh_sport;               /* source port */
 u_short uh_dport;               /* destination port */
 u_short uh_ulen;                /* udp length */
 u_short uh_sum;                 /* udp checksum */
};

struct sctphdr {
 u_short sh_sport;               /* source port */
 u_short sh_dport;               /* destination port */
 u_int32_t	sh_vtag;			/* verification tag */
 u_int32_t	sh_sum;			/* checksum */
};
////////////////////////////////////////////////////////////
// Vector template
////////////////////////////////////////////////////////////

template < class Type > class Vector
{

public:
  int size;
  int actual;
  Type **ar;

public:
  Vector ();
  Vector (Vector & a);
  ~Vector ();
  Vector & operator = (Vector & a);
  Type & operator[](int idx);
  Type *elementAt (int idx);
  bool removeElementAt (int idx);
  int length ();
  void append (Type * ptr);
  void addElement (Type * ptr);
  bool remove (Type * ptr);
  bool removeCurrent();
  bool remove (int idx);
  bool removeElement (Type * ptr);
  bool removeRef (Type * ptr);
  int find (Type * ptr);
  Type *first ();
  Type *last ();
  Type *next ();
  Type *current ();
  Type *prev ();
  bool isEmpty ();
  void destruct ();
};

class protocol_def{
public:
  int id;
  PCAPasp__Types::tf__getMsgLen f_getMsgLen;
  PCAPasp__Types::tf__getMsgStartPos f_getMsgStartPos;
  protocol_def(){};
  ~protocol_def(){};
};

typedef Vector <protocol_def> protocol_def_list;

class Protocol_data {
  public:
    protocol_def_list data_list;
    Protocol_data();
    ~Protocol_data();
    
    void add_protocol(const int id, const PCAPasp__Types::tf__getMsgLen& f_getMsgLen, const PCAPasp__Types::tf__getMsgStartPos& f_getMsgStartPos);
    int get_idx(int id);
    const PCAPasp__Types::tf__getMsgLen& get_f_getMsgLen(int id);
    const PCAPasp__Types::tf__getMsgStartPos& get_f_getMsgStartPos(int id);
};

class Hole {
public:
        u_int16_t first;
        u_int16_t last;
        
        inline Hole() {};
        inline Hole(u_int16_t f, u_int16_t l){first=f;last=l;};
        inline ~Hole() {};
};

typedef Vector <Hole> Holes_list;

class IP_fragment {
public:
        
        IP_fragment();
        ~IP_fragment();
        void clear();
        bool add_fragment(struct ip_header* IPHeader,
                            u_char* IPData);
        bool get_fragment(struct ip_header** IPHeader,
                            u_char** IPData);
        u_int16_t  id;

private:
        u_char*    buffer;
        ip_header* header;
        u_int16_t  buffer_len;
        u_int16_t  data_len;
        Holes_list holes;
};

typedef Vector <IP_fragment> IP_fragment_list;

class IP_fragments {
public:
        IP_fragments();
        ~IP_fragments();
        
        void clear();           // clear the IP fragments 
        bool check();           // check wheter IP fragments exist
        bool add_ip_fragment(struct ip_header** IPHeader,
                             u_char** IPData);
                                // put the IP fragment in the buffer
                                // if an IP packet completly reassembled with
                                // the fragment returns true and set the 
                                // pointers. They must be freed later!!
private:
        IP_fragment_list packet_list;
};


class DumpReader {

public:
        DumpReader();
        ~DumpReader();
	
	bool open(char* fname);		// Tries to open a capture file
	bool setFilter(char* filter_script, bpf_u_int32 netmask = 0xffffff);
        TCPSegment* getNextSegment();
	
private:
	char errbuf[PCAP_ERRBUF_SIZE];	// Buffer for PCAP error messages
	pcap_t *fp; 			// Descriptor of an open capture instance.
	char* captureFilter;            // filter script
	struct bpf_program BPFcode;     // compiled filter
        
        // pointers to the read packets
	struct pcap_pkthdr* actHeader;
     	const u_char* actData;
	struct ether_header* actEthernetHeader;
	u_char* actEthernetData;
	struct ip_header* actIPHeader;
	u_char* actIPData;
	struct tcphdr* actTCPHeader;
	u_char* actTCPData;
        struct udphdr* actUDPHeader;
        u_char* actUDPData;

        struct sctphdr* actSCTPHeader;
        u_char* actSCTPData;

        bool free_ptr;
        IP_fragments fragment_buffer;
	
	int frameCounter;

	bool getNext();                 // Next PCAP packet from
	bool getNextEthernet();         // Next ethernet packet containing IP
	bool getNextIP();               // Next non fragmented IP datagram

};

////////////////////////////////////////////////////////////
// TCPBuffer class
////////////////////////////////////////////////////////////

class TCPBuffer {

  public:

    unsigned long int seq_num;
    size_t length;
    unsigned char* buffer;
    unsigned char* read_poi;
    double timestamp;
    unsigned long int total_length;
    unsigned long int lost_length;
    bool closed;
    bool close_sent;
    
    
  public:
    TCPBuffer();
    ~TCPBuffer();
    void clear();
    bool put(TCPSegment* segment);
    bool ack(TCPSegment* segment);
    
    void rewind();
    size_t get_pos();
    void set_pos(size_t pos);
    size_t get_len();
    unsigned char* get_data();
    size_t get_read_len();
    unsigned char* get_read_data();
    void cut();
    void cut(size_t cut_bytes);
    void log(const char *fmt, ...);
    void dump();
    void log_stat();
    
};


struct SCTP_data_chunk{
  unsigned int tsn;
  unsigned int sid;
  unsigned int ssn;
  unsigned int ppid;
  bool begin;
  bool end;
  unsigned int length;
  unsigned char* data;
};


struct SCTP_chunk{
  unsigned int type;
  unsigned int flags;
  unsigned int length;
  union{
    SCTP_data_chunk data;
    unsigned int ack_tsn;
  } data;
};

typedef Vector <SCTP_chunk> SCTP_chunk_list;

class SCTP_data_fragment{
public:
  bool begin;
  bool end;
  unsigned int tsn;
  unsigned int length;
  unsigned char* data;

  SCTP_data_fragment(SCTP_data_chunk &);
  ~SCTP_data_fragment();  
};

typedef Vector <SCTP_data_fragment> SCTP_data_fragment_list;

class SCTP_message{
public:
  SCTP_message();
  ~SCTP_message();

  bool complete;
  bool first_rcvd;
  bool last_rcvd;
  unsigned int ssn;
  unsigned int first_tsn;
  unsigned int last_tsn;
  unsigned int last_cons_tsn;
  unsigned int ppid;
  SCTP_data_fragment_list *fragments;
  size_t length;
  unsigned char* data;
  double timestamp;

  void add_segment(SCTP_data_chunk &chunk, double time_stamp);
  void free_segments();
  int get_idx(unsigned int tsn);
};

typedef Vector <SCTP_message> SCTP_message_list;

class SCTP_stream{
public:
  SCTP_stream();
  ~SCTP_stream();
  
  unsigned int stream_id;
//  unsigned int low_ssn;
//  unsigned int high_ssn;
  SCTP_message_list message_list;
  
  void add_segment(SCTP_data_chunk &data, double timestamp);
  bool has_message();
  double get_first_ts();
  unsigned char* get_first_message_data();
  size_t get_first_message_data_len();
  void delete_first_message();
  void ack_message(unsigned int ack_tsn);
  
  int get_idx(unsigned int ssn);
  int find_first_message();
};

typedef Vector <SCTP_stream> list_of_SCTP_stream;

class SCTP_Stream_list{
public:

  list_of_SCTP_stream streams;
  unsigned int acked_tsn;

  SCTP_Stream_list();
  ~SCTP_Stream_list();
  

  bool has_message();
  unsigned char* get_first_sctp_data();
  size_t get_first_sctp_data_len();
  double get_first_sctp_timestamp();
  void delete_first_sctp_message();
  bool add_to_stream(SCTP_data_chunk &data, double timestamp);
  void add_stream(SCTP_data_chunk &data, double timestamp);
  void add_segment_to_stream(TCPSegment* segment);
  void ack(TCPSegment* segment);
  void log_stat();
  void dump();
};


////////////////////////////////////////////////////////////
// Peer class
////////////////////////////////////////////////////////////

typedef Vector <TCPSegment> SegmentList;

class Peer {
  
  public:
    //Data that idientify the stream:
    u_short port_src;
    u_short port_dst;
    struct in_addr ip_src;
    struct in_addr ip_dst;
    
    TCPBuffer tcp_buf; 		//Buffer for the processed bytes
    SegmentList seg_list; 	//List for the icoming segments that haven't been processed yet.
    int protocol_type;          //Protocol type of the peer. Type are defined in TCPSegment.hh
    bool out_of_sync;
    int transport_type;
    
    // SCTP stuff
    bool is_sctp;
    SCTP_Stream_list stream_list;
  
  public:
    Peer();
    Peer(TCPSegment* segment);
    ~Peer();
    void reset();
    void init(TCPSegment* segment);
    bool compare(TCPSegment* segment);
    bool sentBy(TCPSegment* segment); //Returns true if the segment was sent by this Peer
    void put(TCPSegment* segment);
    bool ack(TCPSegment* segment);

    
    int get_msg_len();
    bool tryToResync();

    // SCTP stuff
    bool has_message();
    unsigned char* get_first_sctp_data();
    size_t get_first_sctp_data_len();
    double get_first_sctp_timestamp();
    void delete_first_sctp_message();

    
    void log(const char *fmt, ...);
    void dump();
    void log_stat();
};

////////////////////////////////////////////////////////////
// PeerList class
////////////////////////////////////////////////////////////

typedef Vector <Peer> Peers;

class PeerList {

  public:
    Peers peer_list;
    bool tcp;
    
  public:
    PeerList();
    ~PeerList();
    void addPeer(TCPSegment* segment);
    Peer* getPeer(TCPSegment* segment);
    Peer* getOtherPeer(TCPSegment* segment);
    bool sendSegmentToPeer(TCPSegment* segment); //Returns false if lost segment is detected
    void setType(bool t);
    Peer* elementAt(int i);
    int length();
    void log(const char *fmt, ...);
    void dump();
    void log_stat();
};

////////////////////////////////////////////////////////////
// FilterEntry class
////////////////////////////////////////////////////////////

class FilterEntry {

  public:
    int protocol_type;
    struct in_addr ip_src;
    struct in_addr ip_dst;
    unsigned int port_dst;
    bool ip_src_all;

  public:
    FilterEntry(int protocol, struct in_addr sip, bool sip_all, struct in_addr dip, unsigned int rport);
    ~FilterEntry();
    bool compare(TCPSegment* seg);
    void log(const char *fmt, ...);
};

////////////////////////////////////////////////////////////
// FilterTable class
////////////////////////////////////////////////////////////

typedef Vector <FilterEntry> FilterEntries;

class FilterTable {

  public:
    FilterEntries entry_list;
    
  public:
    FilterTable();
    ~FilterTable();
    void addEntry(int protocol, struct in_addr sip, bool sip_all, struct in_addr dip, unsigned int rport);
    int filter(TCPSegment* segment);
    void log(const char *fmt, ...);
};




////////////////////////////////////////////////////////////
// PCAPasp_PT class
////////////////////////////////////////////////////////////
class PCAPasp__PT : public PCAPasp__PT_BASE {

public:
	PCAPasp__PT(const char *par_port_name = NULL);
	~PCAPasp__PT();

	void set_parameter(const char *parameter_name,
		const char *parameter_value);

	void Event_Handler(const fd_set *read_fds,
		const fd_set *write_fds, const fd_set *error_fds,
		double time_since_last_call);
  ESP_handler esp;      
  void inc_msg(const PCAPasp__Types::ASP__PCAP__ESP__Report& data) {incoming_message(data);};
         
protected:
	void user_map(const char *system_port);
	void user_unmap(const char *system_port);

	void user_start();
	void user_stop();
               
	void outgoing_send(const PCAPasp__Types::ASP__PCAP__Capture& send_par);
	void outgoing_send(const PCAPasp__Types::ASP__PCAP__ConfigReq& send_par);
	void outgoing_send(const PCAPasp__Types::ASP__PCAP__MessageReq& send_par);
        void outgoing_send(const PCAPasp__Types::ASP__PCAP__DumpReaderFilter& send_par);
        void outgoing_send(const PCAPasp__Types::ASP__PACP__SetupProtocol& send_par);
        void outgoing_send(const PCAPasp__Types::ASP__PCAP__ESP__Setup& send_par);
        
        TCPSegment* getNextFilteredSegment();
        void log(const char *fmt, ...);
	
        // Variables for capturing mode
	int capture;
	int settings;
	pcap_t *handle;
	struct pcap_pkthdr header;
	pcap_dumper_t *dumpfile;
        // For test port parameters
        char* capture_file;
        char* packet_filter;
        
        
        // Inner components
        DumpReader dump_reader;   // I/f for PCAP dump files
        PeerList peer_list_tcp;   // Peer buffer list for TCP streams
        PeerList peer_list_udp;   // Peer buffer list for UDP streams
        PeerList peer_list_sctp;   // Peer buffer list for SCTP streams
        FilterTable filter_table; // Stream filter table

};

}
#endif
