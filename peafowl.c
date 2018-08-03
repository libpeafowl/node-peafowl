#include <node_api.h>
#include <napi-macros.h>
#include <stdio.h>
#include <stdlib.h>
#include "peafowl_lib/src/api.h"

#define SIZE_IPv4_FLOW_TABLE 32767
#define SIZE_IPv6_FLOW_TABLE 32767
#define MAX_IPv4_ACTIVE_FLOWS 500000
#define MAX_IPv6_ACTIVE_FLOWS 500000

dpi_library_state_t* state; // the state

// init state
int init(int flag)
{
  int ret;

  if(flag != 0 || flag != 1) {
    fprintf(stderr, "Parameters different to 0 or 1. No init()\n");
    exit(-1); // ERROR
  }
  
  if(state == 0){ }// TODO stateless
  else {
    state = dpi_init_stateful(SIZE_IPv4_FLOW_TABLE, SIZE_IPv6_FLOW_TABLE, MAX_IPv4_ACTIVE_FLOWS, MAX_IPv6_ACTIVE_FLOWS);
  }

  if(state == NULL) {
    fprintf(stderr, "dpi_init_stateful ERROR\n");
    exit(-1); // ERROR
  }

  return 0;
  
}

// identify protocols
int get_protocol(const u_char* packet, struct pcap_pkthdr *header){

  dpi_identification_result_t r;
  int ID_protocol = -1;

  r = dpi_stateful_identify_application_protocol(state, packet+sizeof(struct ether_header),
						 header->len-sizeof(struct ether_header), time(NULL));

  if(r.protocol.l4prot == IPPROTO_UDP){
    if(r.protocol.l7prot < DPI_NUM_UDP_PROTOCOLS){
      /* stats.parsed_packets++; */
      return r.protocol.l7prot;
    }
  } else if(r.protocol.l4prot == IPPROTO_TCP){
    if(r.protocol.l7prot < DPI_NUM_TCP_PROTOCOLS){
      /* stats.parsed_packets++; */
      return DPI_NUM_UDP_PROTOCOLS + r.protocol.l7prot;
    }
  }
  return ID_protocol;
}

// terminate
void terminate()
{
  dpi_terminate(state);
}


NAPI_METHOD(pfw_init_state) {

  int r;
  
  NAPI_ARGV(1);
  NAPI_ARGV_INT32(number, 1);
  r = init(number);
  NAPI_RETURN_INT32(r);
}


NAPI_METHOD(pfw_get_protocol) {

  int res;
  NAPI_ARGV(2);
  NAPI_ARGV_BUFFER(packet, 0);
  NAPI_ARGV_BUFFER_CAST(struct pcap_pkthdr *, header, 1);
  res = get_protocol(packet, header);
  NAPI_RETURN_INT32(number);
}


NAPI_METHOD(pfw_terminate) {
  
  terminate();
  return NULL;
}


NAPI_INIT() {
  NAPI_EXPORT_FUNCTION(pfw_init);
  NAPI_EXPORT_FUNCTION(pfw_get_protocol);
  NAPI_EXPORT_FUNCTION(pfw_terminate);
}
