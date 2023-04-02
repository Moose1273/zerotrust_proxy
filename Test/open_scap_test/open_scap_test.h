// #include "openscap.h"
// #include "Util/OpenSCAP/openscap/src/common/public/oscap.h"
// #include "Util/OpenSCAP/openscap/src/common/public/oscap_reference.h"
// #include "Util/OpenSCAP/openscap/src/XCCDF/public/xccdf_benchmark.h"
// #include "Util/OpenSCAP/openscap/src/XCCDF_POLICY/public/xccdf_policy.h"
// #include "Util/OpenSCAP/openscap/src/XCCDF_POLICY/public/check_engine_plugin.h"
extern "C"
{
#include <openscap/oscap.h>
#include <openscap/xccdf_benchmark.h>
#include <openscap/xccdf_policy.h>
}

#include <iostream>
#include <fstream>
#include <stdlib.h>