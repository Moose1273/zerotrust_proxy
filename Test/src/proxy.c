#include "proxy.h"
#include "../suricata/suricata/src/suricata.h"
void startSuricata(int argc, char** argv)
{
    SuricataMain(argc, argv);
}

void stopSuricata()
{
    EngineStop();
}

