
#include "baby_logger.h"

int main(int argc, char *argv[])
{

  logger::InitLogging("My app");
  LOG(DEBUG) << "DEBUG LOG IS ENABLED";

  return 0;
}
