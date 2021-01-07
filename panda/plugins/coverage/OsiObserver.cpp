#include "osi_subject.h"
#include "OsiObserver.h"

namespace coverage
{

OsiObserver::~OsiObserver()
{
    unregister_osi_observer(this);
}

}
