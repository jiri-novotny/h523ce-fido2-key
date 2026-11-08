#include <stdbool.h>

#include "update.h"

static bool do_reset = false;

/* Public functions ----------------------------------------------------------*/

void schedule_reset(void)
{
  do_reset = true;
}

bool should_reset(void)
{
  return do_reset;
}
