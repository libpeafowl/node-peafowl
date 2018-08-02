#ifndef NAPI_MACROS
#define NAPI_MACROS

#define NAPI_INIT() \
  static void napi_macros_init(napi_env env, napi_value exports); \
  napi_value napi_macros_init_wrap (napi_env env, napi_value exports) { \
    napi_macros_init(env, exports); \
    return exports; \
  } \
  NAPI_MODULE(NODE_GYP_MODULE_NAME, napi_macros_init_wrap) \
  static void napi_macros_init (napi_env env, napi_value exports)

#define NAPI_METHOD(name) \
  napi_value name (napi_env env, napi_callback_info info)

#define NAPI_UV_THROWS(err, fn) \
  err = fn; \
  if (err < 0) { \
    napi_throw_error(env, uv_err_name(err), uv_strerror(err)); \
    return NULL; \
  }

#define NAPI_EXPORT_ALIGNMENTOF(name) \
  napi_value name##_alignmentof; \
  { \
    struct tmp { \
      char a; \
      name b; \
    }; \
    napi_create_uint32(env, sizeof(struct tmp) - sizeof(name), &name##_alignmentof); \
    napi_set_named_property(env, exports, "alignmentof_" #name, name##_alignmentof); \
  }

#define NAPI_EXPORT_ALIGNMENTOF_STRUCT(name) \
  napi_value name##_alignmentof; \
  { \
    struct tmp { \
      char a; \
      struct name b; \
    }; \
    napi_create_uint32(env, sizeof(struct tmp) - sizeof(struct name), &name##_alignmentof); \
    napi_set_named_property(env, exports, "alignmentof_" #name, name##_alignmentof); \
  }

#define NAPI_EXPORT_SIZEOF(name) \
  napi_value name##_sizeof; \
  napi_create_uint32(env, sizeof(name), &name##_sizeof); \
  napi_set_named_property(env, exports, "sizeof_" #name, name##_sizeof);

#define NAPI_EXPORT_SIZEOF_STRUCT(name) \
  napi_value name##_sizeof; \
  napi_create_uint32(env, sizeof(struct name), &name##_sizeof); \
  napi_set_named_property(env, exports, "sizeof_" #name, name##_sizeof);

#define NAPI_EXPORT_UINT32(name) \
  napi_value name##_uint32; \
  napi_create_uint32(env, name, &name##_uint32); \
  napi_set_named_property(env, exports, #name, name##_uint32);

#define NAPI_EXPORT_INT32(name) \
  napi_value name##_int32; \
  napi_create_int32(env, name, &name##_int32); \
  napi_set_named_property(env, exports, #name, name##_int32);

#define NAPI_EXPORT_FUNCTION(name) \
  napi_value name##_fn; \
  napi_create_function(env, NULL, 0, name, NULL, &name##_fn); \
  napi_set_named_property(env, exports, #name, name##_fn);

#define NAPI_EXPORT_UTF8(name, len) \
  napi_value name##_utf8; \
  napi_create_string_utf8(env, name, len, &name##_utf8); \
  napi_set_named_property(env, exports, #name, name##_utf8);

#define NAPI_EXPORT_STRING(name) \
  NAPI_EXPORT_UTF8(name, NAPI_AUTO_LENGTH)

#define NAPI_RETURN_INT32(name) \
  napi_value return_int32; \
  napi_create_int32(env, name, &return_int32); \
  return return_int32;

#define NAPI_RETURN_UINT32(name) \
  napi_value return_uint32; \
  napi_create_uint32(env, name, &return_uint32); \
  return return_uint32;

#define NAPI_RETURN_UTF8(name, len) \
  napi_value return_utf8; \
  napi_create_string_utf8(env, name, len, &return_utf8); \
  return return_utf8;

#define NAPI_RETURN_STRING(name) \
  NAPI_RETURN_UTF8(name, NAPI_AUTO_LENGTH)

#define NAPI_UTF8(name, size, val) \
  char name[size]; \
  size_t name##_len; \
  if (napi_get_value_string_utf8(env, val, (char *) &name, size, &name##_len) != napi_ok) { \
    napi_throw_error(env, "EINVAL", "Expected string"); \
    return NULL; \
  }

#define NAPI_UINT32(name, val) \
  uint32_t name; \
  if (napi_get_value_uint32(env, val, &name) != napi_ok) { \
    napi_throw_error(env, "EINVAL", "Expected unsigned number"); \
    return NULL; \
  }

#define NAPI_INT32(name, val) \
  int32_t name; \
  if (napi_get_value_int32(env, val, &name) != napi_ok) { \
    napi_throw_error(env, "EINVAL", "Expected number"); \
    return NULL; \
  }

#define NAPI_BUFFER_CAST(type, name, val) \
  type name; \
  size_t name##_len; \
  napi_get_buffer_info(env, val, (void **) &name, &name##_len);

#define NAPI_BUFFER(name, val) \
  NAPI_BUFFER_CAST(char *, name, val)

#define NAPI_FOR_EACH(arr, element) \
  uint32_t arr##_len; \
  napi_get_array_length(env, arr, &arr##_len); \
  napi_value element; \
  for (uint32_t i = 0; i < arr##_len && napi_get_element(env, arr, i, &element) == napi_ok; i++)

#define NAPI_ARGV(n) \
  napi_value argv[n]; \
  size_t argc = n; \
  napi_get_cb_info(env, info, &argc, argv, NULL, NULL);

#define NAPI_ARGV_UTF8(name, size, i) \
  NAPI_UTF8(name, size, argv[i])

#define NAPI_ARGV_UINT32(name, i) \
  NAPI_UINT32(name, argv[i])

#define NAPI_ARGV_INT32(name, i) \
  NAPI_INT32(name, argv[i])

#define NAPI_ARGV_BUFFER_CAST(type, name, i) \
  NAPI_BUFFER_CAST(type, name, argv[i])

#define NAPI_ARGV_BUFFER(name, i) \
  NAPI_ARGV_BUFFER_CAST(char *, name, i)

#endif

