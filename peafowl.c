#include <node_api.h>
#include <napi-macros.h>
#include "peafowl_lib/src/api.h"

#define SIZE_IPv4_FLOW_TABLE 32767
#define SIZE_IPv6_FLOW_TABLE 32767
#define MAX_IPv4_ACTIVE_FLOWS 500000
#define MAX_IPv6_ACTIVE_FLOWS 500000

dpi_library_state_t* state; // the state

// init state
int init_state(int flag)
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
int dpi_identification()
{
  dpi_identification_result_t *r;

  r = malloc(sizeof(dpi_identification_result_t));
  if(r == NULL) {
    fprintf(stderr, " malloc() error");
    exit(-1);
  }
  
  r = dpi_stateful_identify_application_protocol(state, packet+ip_offset, 
						 header.caplen-ip_offset, time(NULL))

    return r.protocol.l7prot; // return APP proto number
}

// terminate
void terminate()
{
  dpi_terminate(state);
}


NAPI_METHOD(init_state) {

  int r;
  
  NAPI_ARGV(1);
  NAPI_ARGV_INT32(number, 1);
  r = init_state();
  NAPI_RETURN_INT32(r);
}


NAPI_METHOD(dpi_identification) {

  int res;
  
  res = dpi_identification();
  NAPI_RETURN_INT32(number);
}


NAPI_METHOD(terminate) {
  
  terminate();
  return NULL;
}


NAPI_INIT() {
  NAPI_EXPORT_FUNCTION(init_state);
  NAPI_EXPORT_FUNCTION(dpi_identification);
  NAPI_EXPORT_FUNCTION(terminate);
}
