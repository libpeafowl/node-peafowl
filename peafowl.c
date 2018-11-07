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

// global definition for wrapping //
pfwl_state_t* state;         // the state
pfwl_dissection_info_t *r;   // the dissection info struct
struct pcap_pkthdr* header;  // the header of pkt


/* ############## C IMPL OF PEAFOWL FUNCTIONS ############## */
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


// Converts a pcap datalink type to a pfwl_datalink_type_t
pfwl_protocol_l2_t _convert_pcap_dlt(int link_type)
{
    return pfwl_convert_pcap_dlt(link_type);
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


// enables an L7 protocol dissector
uint8_t _protocol_L7_enable(pfwl_state_t *state,
                            pfwl_protocol_l7_t protocol)
{
    return pfwl_protocol_l7_enable(state, protocol);
}


// disables an L7 protocol dissector
uint8_t _protocol_L7_disable(pfwl_state_t *state,
                            pfwl_protocol_l7_t protocol)
{
    return pfwl_protocol_l7_disable(state, protocol);
}


// guesses the protocol looking only at source/destination ports
pfwl_protocol_l7_t _guess_protocol(pfwl_dissection_info_t guess_info)
{
    return pfwl_guess_protocol(guess_info);
}


// returns the string represetation of a protocol
char* _get_L7_protocol_name(pfwl_protocol_l7_t protocol)
{
    return pfwl_get_L7_protocol_name(protocol);
}


// returns the protocol id corresponding to a protocol string
pfwl_protocol_l7_t _get_L7_protocol_id(char* string)
{
    return pfwl_get_L7_protocol_id(string);
}


// dissect pachet from L2 and return the L7 protocol name
char* _get_L7_from_L2(char* packet, struct pcap_pkthdr* header, int link_type)
{
    char* name = NULL;
    /* pfwl_dissection_info_t r; */
    // convert L2 type in L2 peafowl type
    pfwl_protocol_l2_t dlt = pfwl_convert_pcap_dlt(link_type);
    // call dissection from L2
    pfwl_status_t status = pfwl_dissect_from_L2(state, (const u_char*) packet,
                                                header->caplen, time(NULL), dlt, r);

    if(status >= PFWL_STATUS_OK) {
        name = pfwl_get_L7_protocol_name(r->l7.protocol);
        return name;
    }
    else return "ERROR";
}


// enables the extraction of a specific L7 field for a given protocol
uint8_t _field_add_L7(pfwl_state_t* state, pfwl_field_id_t field)
{
    return pfwl_field_add_L7(state, field);
}


// disables the extraction of a specific L7 field for a given protocol
uint8_t _field_remove_L7(pfwl_state_t* state, pfwl_field_id_t field)
{
    return pfwl_field_remove_L7(state, field);
}


// set the accuracy level of dissection
uint8_t _set_protocol_accuracy_L7(pfwl_state_t* state,
                                  pfwl_protocol_l7_t protocol,
                                  pfwl_dissector_accuracy_t accuracy)
{
    return pfwl_set_protocol_accuracy_L7(state, protocol, accuracy);
}


// extracts a specific string field from a list of fields (ret = 0 string set)
uint8_t _field_string_get(pfwl_field_t* fields,
                          pfwl_field_id_t id,
                          pfwl_string_t* string)
{
    return pfwl_field_string_get(fields, id, string);
}


// extracts a specific numeric field from a list of fields (ret = 0 number set)
uint8_t _field_number_get(pfwl_field_t* fields,
                          pfwl_field_id_t id,
                          int64_t* number)
{
    return pfwl_field_number_get(fields, id, number);
}


// extracts a pair in a specific position, from a specific array field (ret = 0 pair set)
uint8_t _field_array_get_pair(pfwl_field_t *fields,
                              pfwl_field_id_t id,
                              size_t position,
                              pfwl_pair_t *pair)
{
    return pfwl_field_array_get_pair(fields, id, position, pair);
}


// extract specific HTTP header (ret = 0, header_value is set)
uint8_t _http_get_header(pfwl_dissection_info_t *dissection_info,
                         char *header_name,
                         pfwl_string_t *header_value)
{
    return pfwl_http_get_header(dissection_info, header_name, header_value);
}


// checks if a specific L7 protocol has been identified in a given dissection info
// NOTE: protocols are associated to flows and not to packets
uint8_t _has_protocol_L7(pfwl_dissection_info_t* dissection_info,
                         pfwl_protocol_l7_t protocol)
{
    return pfwl_has_protocol_L7(dissection_info, protocol);
}


// terminate
void _terminate()
{
  pfwl_terminate(state);
}
/* ############## ############## ############## ############## ############## ############## */


/* ############## NAPI METHODS ############## */
NAPI_METHOD(init) {
    int r;
    r = b_init();
    NAPI_RETURN_INT32(r);
}

NAPI_METHOD(convert_pcap_dlt) {
    pfwl_protocol_l2_t plt;
    NAPI_ARGV(1);
    NAPI_ARGV_UINT32(dlt, 0);
    plt = _convert_pcap_dlt(dlt);
    NAPI_RETURN_UINT32(plt);
}

NAPI_METHOD(dissect_from_L2) {
    pfwl_status_t status;
    NAPI_ARGV(6);
    NAPI_ARGV_BUFFER_CAST(pfwl_state_t*, state, 0);
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
    NAPI_ARGV_BUFFER_CAST(pfwl_state_t*, state, 0);
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
    NAPI_ARGV_BUFFER_CAST(pfwl_state_t*, state, 0);
    NAPI_ARGV_BUFFER(pkt, 1);  // pkt from L4
    NAPI_ARGV_UINT32(len, 2);  // len from L4
    NAPI_ARGV_INT32(time, 3);
    NAPI_ARGV_BUFFER_CAST(pfwl_dissection_info_t*, d_info, 4);
    status = _dissect_from_L4(state, pkt, len, time, d_info);
    NAPI_RETURN_UINT32(status);
}

NAPI_METHOD(protocol_L7_enable) {
    uint8_t status;
    NAPI_ARGV(2);
    NAPI_ARGV_BUFFER_CAST(pfwl_state_t*, state, 0);
    NAPI_ARGV_UINT32(proto, 1);
    status = _protocol_L7_enable(state, proto);
    NAPI_RETURN_UINT32(status);
}

NAPI_METHOD(protocol_L7_disable) {
    uint8_t status;
    NAPI_ARGV(2);
    NAPI_ARGV_BUFFER_CAST(pfwl_state_t*, state, 0);
    NAPI_ARGV_UINT32(proto, 1);
    status = _protocol_L7_disable(state, proto);
    NAPI_RETURN_UINT32(status);
}

NAPI_METHOD(guess_protocol) {
    uint8_t status;
    NAPI_ARGV(1);
    NAPI_ARGV_BUFFER_CAST(pfwl_dissection_info_t, g_info, 0);
    status = _guess_protocol(g_info);
    NAPI_RETURN_UINT32(status);
}

NAPI_METHOD(get_L7_protocol_name) {
    char* name;
    NAPI_ARGV(1);
    NAPI_ARGV_UINT32(proto, 0);
    name = _get_L7_protocol_name(proto);
    NAPI_RETURN_STRING(name);
}

NAPI_METHOD(get_L7_protocol_id) {
    uint8_t id;
    NAPI_ARGV(1);
    NAPI_ARGV_BUFFER(string, 0);
    id = _get_L7_protocol_id(string);
    NAPI_RETURN_UINT32(id);
}

NAPI_METHOD(get_L7_from_L2) {
    char *name;
    NAPI_ARGV(3);
    NAPI_ARGV_BUFFER(packet, 0);
    NAPI_ARGV_BUFFER_CAST(struct pcap_pkthdr *, header, 1);
    NAPI_ARGV_INT32(link_type, 2);
    name = _get_L7_from_L2(packet, header, link_type);
    NAPI_RETURN_STRING(name);
}

NAPI_METHOD(field_add_L7) {
    uint8_t status;
    NAPI_ARGV(2);
    NAPI_ARGV_BUFFER_CAST(pfwl_state_t*, state, 0);
    NAPI_ARGV_UINT32(field, 1);
    status = _field_add_L7(state, field);
    NAPI_RETURN_UINT32(status);
}

NAPI_METHOD(field_remove_L7) {
    uint8_t status;
    NAPI_ARGV(2);
    NAPI_ARGV_BUFFER_CAST(pfwl_state_t*, state, 0);
    NAPI_ARGV_UINT32(field, 1);
    status = _field_remove_L7(state, field);
    NAPI_RETURN_UINT32(status);
}

NAPI_METHOD(set_protocol_accuracy_L7) {
    uint8_t status;
    NAPI_ARGV(3);
    NAPI_ARGV_BUFFER_CAST(pfwl_state_t*, state, 0);
    NAPI_ARGV_UINT32(proto, 1);
    NAPI_ARGV_UINT32(accuracy, 2);
    status = _set_protocol_accuracy_L7(state, proto, accuracy);
    NAPI_RETURN_UINT32(status);
}

NAPI_METHOD(field_string_get) {
    uint8_t status;
    NAPI_ARGV(3);
    NAPI_ARGV_BUFFER_CAST(pfwl_field_t*, fields, 0);
    NAPI_ARGV_UINT32(id, 1);
    NAPI_ARGV_BUFFER_CAST(pfwl_string_t*, string, 2);
    status = _field_string_get(fields, id, string);
    NAPI_RETURN_UINT32(status);
}

NAPI_METHOD(field_number_get) {
    uint8_t status;
    NAPI_ARGV(3);
    NAPI_ARGV_BUFFER_CAST(pfwl_field_t*, fields, 0);
    NAPI_ARGV_UINT32(id, 1);
    NAPI_ARGV_BUFFER_CAST(int64_t*, number, 2);
    status = _field_number_get(fields, id, number);
    NAPI_RETURN_UINT32(status);
}

NAPI_METHOD(field_array_get_pair) {
    uint8_t status;
    NAPI_ARGV(4);
    NAPI_ARGV_BUFFER_CAST(pfwl_field_t*, fields, 0);
    NAPI_ARGV_UINT32(id, 1);
    NAPI_ARGV_UINT32(pos, 2);
    NAPI_ARGV_BUFFER_CAST(pfwl_pair_t*, pair, 3);
    status = _field_array_get_pair(fields, id, pos, pair);
    NAPI_RETURN_UINT32(status);
}

NAPI_METHOD(http_get_header) {
    uint8_t status;
    NAPI_ARGV(3);
    NAPI_ARGV_BUFFER_CAST(pfwl_dissection_info_t*, d_info, 0);
    NAPI_ARGV_BUFFER(h_name, 1);
    NAPI_ARGV_BUFFER_CAST(pfwl_string_t*, h_val, 2);
    status = _http_get_header(d_info, h_name, h_val);
    NAPI_RETURN_UINT32(status);
}

NAPI_METHOD(has_protocol_L7) {
    uint8_t status;
    NAPI_ARGV(2);
    NAPI_ARGV_BUFFER_CAST(pfwl_dissection_info_t*, d_info, 0);
    NAPI_ARGV_UINT32(proto, 1);
    status = _has_protocol_L7(d_info, proto);
    NAPI_RETURN_UINT32(status);
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
/* ############## ############## ############## */


/* ############## EXPORTED FUNCTIONS ############## */
NAPI_INIT() {
  NAPI_EXPORT_FUNCTION(init);
  NAPI_EXPORT_FUNCTION(convert_pcap_dlt);
  NAPI_EXPORT_FUNCTION(dissect_from_L2);
  NAPI_EXPORT_FUNCTION(dissect_from_L3);
  NAPI_EXPORT_FUNCTION(dissect_from_L4);
  NAPI_EXPORT_FUNCTION(protocol_L7_enable);
  NAPI_EXPORT_FUNCTION(protocol_L7_disable);
  NAPI_EXPORT_FUNCTION(guess_protocol);
  NAPI_EXPORT_FUNCTION(get_L7_protocol_name);
  NAPI_EXPORT_FUNCTION(get_L7_protocol_id);
  NAPI_EXPORT_FUNCTION(get_L7_from_L2);
  NAPI_EXPORT_FUNCTION(field_add_L7);
  NAPI_EXPORT_FUNCTION(field_remove_L7);
  NAPI_EXPORT_FUNCTION(set_protocol_accuracy_L7);
  NAPI_EXPORT_FUNCTION(field_string_get);
  NAPI_EXPORT_FUNCTION(field_number_get);
  NAPI_EXPORT_FUNCTION(field_array_get_pair);
  NAPI_EXPORT_FUNCTION(http_get_header);
  NAPI_EXPORT_FUNCTION(has_protocol_L7);
  NAPI_EXPORT_FUNCTION(terminate);
  NAPI_EXPORT_FUNCTION(test_mul);
}
/* ############## ############## ############## */
