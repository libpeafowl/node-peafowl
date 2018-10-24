#include <node_api.h>
#include <napi-macros.h>
#include <stdio.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <pcap.h>
#include <time.h>
#include "peafowl_lib/include/peafowl/peafowl.h"

#define BUFF 10

pfwl_state_t* state; // the state

struct pcap_pkthdr* header;

// init state
int init()
{
  // C function from Peafowl lib
  state = pfwl_init();
  if(state == NULL) {
      fprintf(stderr, "peafowl init ERROR\n");
      return -1; // ERROR
  }
  return 0;
}

/**
 * NOT YET IMPLEMENTED WITH NAPI-MACROS ******************************************************
 */
// parse packet from L2
pfwl_dissection_info_t* parse_packet_l2(char* packet, uint32_t link_type)
{
    pfwl_dissection_info_t* r = NULL;
    pfwl_status_t status = pfwl_dissect_from_L2(state, (const u_char*) packet,
                                                header->caplen, time(NULL), link_type, r);
    if(status == PFWL_STATUS_OK)
        return r;
    else
        return NULL;
}

// parse packet from L3
pfwl_dissection_info_t* parse_packet_l3(char* packet, uint32_t l2_off)
{
    pfwl_dissection_info_t* r = NULL;
    pfwl_status_t status = pfwl_dissect_from_L3(state, (const u_char*) packet+l2_off,
                                                header->len-l2_off, time(NULL), r);
    if(status == PFWL_STATUS_OK)
        return r;
    else
        return NULL;
}

// parse packet from L4
pfwl_dissection_info_t* parse_packet_l4(char* packet, uint32_t l2_off, uint32_t l3_off)
{
    pfwl_dissection_info_t* r = NULL;
    pfwl_status_t status = pfwl_dissect_from_L4(state, (const u_char*) packet+(l2_off+l3_off),
                                                header->len-(l2_off+l3_off), time(NULL), r);
    if(status == PFWL_STATUS_OK)
        return r;
    else
        return NULL;
}
/**
*********************************************************************************************
*********************************************************************************************/

// dissect pachet and return the L7 protocol name
char* get_L7_protocol_name(char* packet, struct pcap_pkthdr* header, int link_type)
{
    char* name = NULL;
    pfwl_dissection_info_t r;
    // convert L2 type in L2 peafowl type
    pfwl_protocol_l2_t dlt = pfwl_convert_pcap_dlt(link_type);
    // call dissection from L2
    pfwl_status_t status = pfwl_dissect_from_L2(state, (const u_char*) packet,
                                                header->caplen, time(NULL), dlt, &r);

    if(status >= PFWL_STATUS_OK) {
        name = pfwl_get_L7_protocol_name(r.l7.protocol);
        return name;
    }
    else return "ERROR";
}

// terminate
void terminate()
{
  pfwl_terminate(state);
}


/*** NAPI METHODS ***/

NAPI_METHOD(bind_pfwl_init) {
  int r;
  r = init();
  NAPI_RETURN_INT32(r);
}

NAPI_METHOD(bind_pfwl_get_protocol_l7) {
  char *name;
  NAPI_ARGV(3);
  NAPI_ARGV_BUFFER(packet, 0);
  NAPI_ARGV_BUFFER_CAST(struct pcap_pkthdr *, header, 1);
  NAPI_ARGV_INT32(link_type, 2);
  name = get_L7_protocol_name(packet, header, link_type);
  NAPI_RETURN_STRING(name);
}

NAPI_METHOD(bind_pfwl_terminate) {
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
  NAPI_EXPORT_FUNCTION(bind_pfwl_init);
  NAPI_EXPORT_FUNCTION(bind_pfwl_get_protocol_l7);
  NAPI_EXPORT_FUNCTION(bind_pfwl_terminate);
  NAPI_EXPORT_FUNCTION(test_mul);
}
