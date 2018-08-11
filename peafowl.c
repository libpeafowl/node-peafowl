#include <node_api.h>
#include <napi-macros.h>
#include <stdio.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <pcap.h>
#include <time.h>
#include "peafowl_lib/src/api.h"

#define SIZE_IPv4_FLOW_TABLE 32767
#define SIZE_IPv6_FLOW_TABLE 32767
#define MAX_IPv4_ACTIVE_FLOWS 500000
#define MAX_IPv6_ACTIVE_FLOWS 500000

#define BUFF 10

dpi_library_state_t* state; // the state

struct pcap_pkthdr* header;

// init state
int init()
{
  // C function from Peafowl lib
  state = dpi_init_stateful(SIZE_IPv4_FLOW_TABLE, SIZE_IPv6_FLOW_TABLE, MAX_IPv4_ACTIVE_FLOWS, MAX_IPv6_ACTIVE_FLOWS);
  if(state == NULL) {
    fprintf(stderr, "dpi_init_stateful ERROR\n");
    return -1; // ERROR
  }

  return 0; 
}

// identify protocols name L7
char * get_protocol_l7(char* packet, struct pcap_pkthdr *header)
{
  dpi_identification_result_t r;
  char* name = NULL;

  r = dpi_get_protocol(state, (const u_char*) packet+sizeof(struct ether_header),
		       header->len-sizeof(struct ether_header), time(NULL));

  name = calloc(BUFF, sizeof(char));
  if(name == NULL) {
    fprintf(stderr, "calloc ERROR\n");
    return NULL; // ERROR
  }
  name = dpi_get_protocol_string(r.protocol.l7prot);

  return name;    

}

// identify protocols name L4
char * get_protocol_l4(char* packet, struct pcap_pkthdr *header)
{
  dpi_identification_result_t r;
  char* name = NULL;

  r = dpi_get_protocol(state, (const u_char*) packet+sizeof(struct ether_header),
		       header->len-sizeof(struct ether_header), time(NULL));

  name = calloc(BUFF, sizeof(char));
  if(name == NULL){
    fprintf(stderr, "calloc ERROR\n");
    return NULL; // ERROR
  }

  // Check for L4
  if(r.protocol.l4prot == IPPROTO_UDP){
    memcpy(name, "UDP", 3);
    return name;
  } else if(r.protocol.l4prot == IPPROTO_TCP){
    memcpy(name, "TCP", 3);
    return name;
  }
  memcpy(name, "Unknow", strlen("Unknow"));
  return name;
}

// identify protocols pairs [L7,L4]
char * get_protocol_pair(char* packet, struct pcap_pkthdr *header)
{
  dpi_identification_result_t r;
  char * res;
  
  res = malloc(2 * sizeof(char));
  if(res == NULL){
    fprintf(stderr, "malloc ERROR\n");
    return NULL; // ERROR
  }
  memset(res,-1,2);

  r = dpi_get_protocol(state, (const u_char*) packet+sizeof(struct ether_header),
		       header->len-sizeof(struct ether_header), time(NULL));
  
  if(r.protocol.l4prot == IPPROTO_UDP){
    res[0] = IPPROTO_UDP;
    if(r.protocol.l7prot < DPI_NUM_UDP_PROTOCOLS){
      /* stats.parsed_packets++; */
      res[1] = r.protocol.l7prot;
      return res;
    }
  } else if(r.protocol.l4prot == IPPROTO_TCP){
    res[0] = IPPROTO_TCP;
    if(r.protocol.l7prot < DPI_NUM_TCP_PROTOCOLS){
      /* stats.parsed_packets++; */
      res[1] = DPI_NUM_UDP_PROTOCOLS + r.protocol.l7prot;
      return res;
    }
  }
  return res;
}

// terminate
void terminate()
{
  dpi_terminate(state);
}


/*** NAPI METHODS ***/

NAPI_METHOD(pfw_init) {
  int r;
  r = init();
  NAPI_RETURN_INT32(r);
}


NAPI_METHOD(pfw_get_protocol_l7) {
  char *name;
  NAPI_ARGV(2);
  NAPI_ARGV_BUFFER(packet, 0);
  NAPI_ARGV_BUFFER_CAST(struct pcap_pkthdr *, header, 1);
  name = get_protocol_l7(packet, header);
  NAPI_RETURN_STRING(name);
}

NAPI_METHOD(pfw_get_protocol_l4) {
  char *name;
  NAPI_ARGV(2);
  NAPI_ARGV_BUFFER(packet, 0);
  NAPI_ARGV_BUFFER_CAST(struct pcap_pkthdr *, header, 1);
  name = get_protocol_l4(packet, header);
  NAPI_RETURN_STRING(name);
}

NAPI_METHOD(pfw_get_protocol_pair) {
  char *res;
  NAPI_ARGV(2);
  NAPI_ARGV_BUFFER(packet, 0);
  NAPI_ARGV_BUFFER_CAST(struct pcap_pkthdr *, header, 1);
  res = get_protocol_pair(packet, header);
  NAPI_RETURN_UTF8(res, 2);
}


NAPI_METHOD(pfw_terminate) {
  terminate();
  return NULL;
}


/* ### FOR TEST ### */
NAPI_METHOD(test_mul) {
  NAPI_ARGV(1)
  NAPI_ARGV_INT32(number, 0)

  number *= 2;

  NAPI_RETURN_INT32(number)
}


NAPI_INIT() {
  NAPI_EXPORT_FUNCTION(pfw_init);
  NAPI_EXPORT_FUNCTION(pfw_get_protocol_l7);
  NAPI_EXPORT_FUNCTION(pfw_get_protocol_l4);
  NAPI_EXPORT_FUNCTION(pfw_get_protocol_pair);
  NAPI_EXPORT_FUNCTION(pfw_terminate);
  NAPI_EXPORT_FUNCTION(test_mul);
}
