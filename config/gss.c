#include <dlfcn.h>
#ifdef __APPLE__
#include <GSS/GSS.h>
#else
#include <gssapi/gssapi.h>
#endif

OM_uint32 (*_gss_display_status)(OM_uint32 *, OM_uint32, int, gss_OID, OM_uint32 *, gss_buffer_t) = NULL;

int main(int argc, char **argv) {
	int retval = 0;
	void *handle;

	char* library =
#ifdef __APPLE__
		"/System/Library/Frameworks/GSS.framework/GSS";
#else
		"libgssapi_krb5.so";
#endif
	handle = dlopen(library, RTLD_LAZY);
	if (handle) {
		_gss_display_status = dlsym(handle, "gss_display_status");
		retval = _gss_display_status != NULL;
		dlclose(handle);
	}

	return !!retval;
}