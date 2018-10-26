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
int b_init()
{
  // C function from Peafowl lib
  state = pfwl_init();
  if(state == NULL) {
      fprintf(stderr, "peafowl init ERROR\n");
      return -1; // ERROR
  }
  return 0;
}

// parse packet from L2
pfwl_status_t _dissect_from_L2(pfwl_state_t* state, char* packet, uint32_t length,
                              uint32_t timestamp, pfwl_protocol_l2_t datalink_type,
                              pfwl_dissection_info_t* dissection_info)
{
    return pfwl_dissect_from_L2(state, (const u_char*) packet,
                                length, time(NULL),
                                datalink_type, dissection_info);
}

// parse packet from L3
pfwl_status_t _dissect_from_L3(pfwl_state_t* state, char* packet_fromL3, uint32_t length_fromL3,
                                   uint32_t timestamp, pfwl_dissection_info_t* dissection_info)
{
    return pfwl_dissect_from_L3(state, (const u_char*) packet_fromL3,
                                length_fromL3, time(NULL), dissection_info);
}

// parse packet from L4
pfwl_status_t _dissect_from_L4(pfwl_state_t* state, char* packet_fromL4, uint32_t length_fromL4,
                                   uint32_t timestamp, pfwl_dissection_info_t* dissection_info)
{
    return pfwl_dissect_from_L3(state, (const u_char*) packet_fromL4,
                                                length_fromL4, time(NULL), dissection_info);
}

// dissect pachet and return the L7 protocol name
char* _get_L7_protocol_name(char* packet, struct pcap_pkthdr* header, int link_type)
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
void _terminate()
{
  pfwl_terminate(state);
}


/*** NAPI METHODS ***/

NAPI_METHOD(init) {
    int r;
    r = b_init();
    NAPI_RETURN_INT32(r);
}

NAPI_METHOD(dissect_from_L2) {
    pfwl_status_t status;
    NAPI_ARGV(6);
    NAPI_ARGV_BUFFER_CAST(pfwl_state_t *, state, 0);
    NAPI_ARGV_BUFFER(pkt, 1);  // pkt from L2
    NAPI_ARGV_UINT32(len, 2);  // len from L2
    NAPI_ARGV_INT32(time, 3);
    NAPI_ARGV_INT32(dl, 4);    // pfwl_protocol_l2_t
    NAPI_ARGV_BUFFER_CAST(pfwl_dissection_info_t*, d_info, 5);
    status = _dissect_from_L2(state, pkt, len, time, dl, d_info);
    NAPI_RETURN_UINT32(status);
}

NAPI_METHOD(dissect_from_L3) {
    pfwl_status_t status;
    NAPI_ARGV(5);
    NAPI_ARGV_BUFFER_CAST(pfwl_state_t *, state, 0);
    NAPI_ARGV_BUFFER(pkt, 1);  // pkt from L3
    NAPI_ARGV_UINT32(len, 2);  // len from L3
    NAPI_ARGV_INT32(time, 3);
    NAPI_ARGV_BUFFER_CAST(pfwl_dissection_info_t*, d_info, 4);
    status = _dissect_from_L3(state, pkt, len, time, d_info);
    NAPI_RETURN_UINT32(status);
}

NAPI_METHOD(dissect_from_L4) {
    pfwl_status_t status;
    NAPI_ARGV(5);
    NAPI_ARGV_BUFFER_CAST(pfwl_state_t *, state, 0);
    NAPI_ARGV_BUFFER(pkt, 1);  // pkt from L4
    NAPI_ARGV_UINT32(len, 2);  // len from L4
    NAPI_ARGV_INT32(time, 3);
    NAPI_ARGV_BUFFER_CAST(pfwl_dissection_info_t*, d_info, 4);
    status = _dissect_from_L4(state, pkt, len, time, d_info);
    NAPI_RETURN_UINT32(status);
}

NAPI_METHOD(get_L7_protocol_name) {
  char *name;
  NAPI_ARGV(3);
  NAPI_ARGV_BUFFER(packet, 0);
  NAPI_ARGV_BUFFER_CAST(struct pcap_pkthdr *, header, 1);
  NAPI_ARGV_INT32(link_type, 2);
  name = _get_L7_protocol_name(packet, header, link_type);
  NAPI_RETURN_STRING(name);
}

NAPI_METHOD(terminate) {
  _terminate();
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
  NAPI_EXPORT_FUNCTION(init);
  NAPI_EXPORT_FUNCTION(dissect_from_L2);
  NAPI_EXPORT_FUNCTION(dissect_from_L3);
  NAPI_EXPORT_FUNCTION(dissect_from_L4);
  NAPI_EXPORT_FUNCTION(get_L7_protocol_name);
  NAPI_EXPORT_FUNCTION(terminate);
  NAPI_EXPORT_FUNCTION(test_mul);
}
