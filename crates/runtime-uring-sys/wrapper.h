/* bindgen entry point. liburing.h pulls in the io_uring UAPI (io_uring.h) and
 * declares the API as `static inline`; we build with generate_inline_functions so
 * bindgen emits extern decls that resolve against the liburing-ffi static lib. */
#include <liburing.h>
