/* Copyright (C) 2009 The Android Open Source Project
**
** This software is licensed under the terms of the GNU General Public
** License version 2, as published by the Free Software Foundation, and
** may be copied, distributed, and modified under those terms.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
*/

#include <math.h>
#include "android/hw-sensors.h"
#include "android/utils/debug.h"
#include "android/utils/misc.h"
#include "android/utils/system.h"
#include "android/hw-qemud.h"
//#include "android/globals.h"
#include "hw/hw.h"
#include "qemu-char.h"
#include "qemu-timer.h"
#include "android/sensors-port.h"

#define  E(...)    derror(__VA_ARGS__)
#define  W(...)    dwarning(__VA_ARGS__)
#define  D(...)  VERBOSE_PRINT(sensors,__VA_ARGS__)
#define  V(...)  VERBOSE_PRINT(init,__VA_ARGS__)

/* define T_ACTIVE to 1 to debug transport communications */
#define  T_ACTIVE  0

#if T_ACTIVE
#define  T(...)  VERBOSE_PRINT(sensors,__VA_ARGS__)
#else
#define  T(...)   ((void)0)
#endif

/* this code supports emulated sensor hardware
 *
 * Note that currently, only the accelerometer is really emulated, and only
 * for the purpose of allowing auto-rotating the screen in keyboard-less
 * configurations.
 *
 *
 */


static const struct {
    const char*  name;
    int          id;
} _sSensors[MAX_SENSORS] = {
#define SENSOR_(x,y)  { y, ANDROID_SENSOR_##x },
  SENSORS_LIST
#undef SENSOR_
};


static int
_sensorIdFromName( const char*  name )
{
    int  nn;
    for (nn = 0; nn < MAX_SENSORS; nn++)
        if (!strcmp(_sSensors[nn].name,name))
            return _sSensors[nn].id;
    return -1;
}

static const char*
_sensorNameFromId( int  id )
{
    int  nn;
    for (nn = 0; nn < MAX_SENSORS; nn++)
        if (id == _sSensors[nn].id)
            return _sSensors[nn].name;
    return NULL;
}

/* For common Sensor Value struct */
typedef struct {
    float a, b, c;
} SensorValues;

typedef struct {
    float   x, y, z;
} Acceleration;


typedef struct {
    float  x, y, z;
} MagneticField;


typedef struct {
    float  azimuth;
    float  pitch;
    float  roll;
} Orientation;


typedef struct {
    float  celsius;
} Temperature;


typedef struct {
    float  value;
} Proximity;

typedef struct {
    char       enabled;
    union {
        SensorValues   value;
        Acceleration   acceleration;
        MagneticField  magnetic;
        Orientation    orientation;
        Temperature    temperature;
        Proximity      proximity;
    } u;
} Sensor;

/*
 * - when the qemu-specific sensors HAL module starts, it sends
 *   "list-sensors"
 *
 * - this code replies with a string containing an integer corresponding
 *   to a bitmap of available hardware sensors in the current AVD
 *   configuration (e.g. "1" a.k.a (1 << ANDROID_SENSOR_ACCELERATION))
 *
 * - the HAL module sends "set:<sensor>:<flag>" to enable or disable
 *   the report of a given sensor state. <sensor> must be the name of
 *   a given sensor (e.g. "accelerometer"), and <flag> must be either
 *   "1" (to enable) or "0" (to disable).
 *
 * - Once at least one sensor is "enabled", this code should periodically
 *   send information about the corresponding enabled sensors. The default
 *   period is 200ms.
 *
 * - the HAL module sends "set-delay:<delay>", where <delay> is an integer
 *   corresponding to a time delay in milli-seconds. This corresponds to
 *   a new interval between sensor events sent by this code to the HAL
 *   module.
 *
 * - the HAL module can also send a "wake" command. This code should simply
 *   send the "wake" back to the module. This is used internally to wake a
 *   blocking read that happens in a different thread. This ping-pong makes
 *   the code in the HAL module very simple.
 *
 * - each timer tick, this code sends sensor reports in the following
 *   format (each line corresponds to a different line sent to the module):
 *
 *      acceleration:<x>:<y>:<z>
 *      magnetic-field:<x>:<y>:<z>
 *      orientation:<azimuth>:<pitch>:<roll>
 *      temperature:<celsius>
 *      sync:<time_us>
 *
 *   Where each line before the sync:<time_us> is optional and will only
 *   appear if the corresponding sensor has been enabled by the HAL module.
 *
 *   Note that <time_us> is the VM time in micro-seconds when the report
 *   was "taken" by this code. This is adjusted by the HAL module to
 *   emulated system time (using the first sync: to compute an adjustment
 *   offset).
 */
#define  HEADER_SIZE  4
#define  BUFFER_SIZE  512

typedef struct HwSensorClient   HwSensorClient;

typedef struct {
    QemudService*       service;
    Sensor              sensors[MAX_SENSORS];
    HwSensorClient*     clients;
    AndroidSensorsPort* sensors_port;
} HwSensors;

struct HwSensorClient {
    HwSensorClient*  next;
    HwSensors*       sensors;
    QemudClient*     client;
    QEMUTimer*       timer;
    uint32_t         enabledMask;
    int32_t          delay_ms;
};

static void
_hwSensorClient_free( HwSensorClient*  cl )
{
    /* remove from sensors's list */
    if (cl->sensors) {
        HwSensorClient**  pnode = &cl->sensors->clients;
        for (;;) {
            HwSensorClient*  node = *pnode;
            if (node == NULL)
                break;
            if (node == cl) {
                *pnode = cl->next;
                break;
            }
            pnode = &node->next;
        }
        cl->next    = NULL;
        cl->sensors = NULL;
    }

    /* close QEMUD client, if any */
    if (cl->client) {
        qemud_client_close(cl->client);
        cl->client = NULL;
    }
    /* remove timer, if any */
    if (cl->timer) {
        qemu_del_timer(cl->timer);
        qemu_free_timer(cl->timer);
        cl->timer = NULL;
    }
    AFREE(cl);
}

/* forward */
static void  _hwSensorClient_tick(void*  opaque);


static HwSensorClient*
_hwSensorClient_new( HwSensors*  sensors )
{
    HwSensorClient*  cl;

    ANEW0(cl);

    cl->sensors     = sensors;
    cl->enabledMask = 0;
    cl->delay_ms    = 800;
    cl->timer       = qemu_new_timer_ns(vm_clock, _hwSensorClient_tick, cl);

    cl->next         = sensors->clients;
    sensors->clients = cl;

    return cl;
}

/* forward */

static void  _hwSensorClient_receive( HwSensorClient*  cl,
                                      uint8_t*         query,
                                      int              querylen );

/* Qemud service management */

static void
_hwSensorClient_recv( void*  opaque, uint8_t*  msg, int  msglen,
                      QemudClient*  client )
{
    HwSensorClient*  cl = opaque;

    _hwSensorClient_receive(cl, msg, msglen);
}

static void
_hwSensorClient_close( void*  opaque )
{
    HwSensorClient*  cl = opaque;

    /* the client is already closed here */
    cl->client = NULL;
    _hwSensorClient_free(cl);
}

/* send a one-line message to the HAL module through a qemud channel */
static void
_hwSensorClient_send( HwSensorClient*  cl, const uint8_t*  msg, int  msglen )
{
    D("%s: '%s'", __FUNCTION__, quote_bytes((const void*)msg, msglen));
    qemud_client_send(cl->client, msg, msglen);
}

static int
_hwSensorClient_enabled( HwSensorClient*  cl, int  sensorId )
{
    return (cl->enabledMask & (1 << sensorId)) != 0;
}

/* this function is called periodically to send sensor reports
 * to the HAL module, and re-arm the timer if necessary
 */
static void
_hwSensorClient_tick( void*  opaque )
{
    HwSensorClient*  cl = opaque;
    HwSensors*       hw  = cl->sensors;
    int64_t          delay = cl->delay_ms;
    int64_t          now_ns;
    uint32_t         mask  = cl->enabledMask;
    Sensor*          sensor;
    char             buffer[128];

    if (_hwSensorClient_enabled(cl, ANDROID_SENSOR_ACCELERATION)) {
        sensor = &hw->sensors[ANDROID_SENSOR_ACCELERATION];
        snprintf(buffer, sizeof buffer, "acceleration:%g:%g:%g",
                 sensor->u.acceleration.x,
                 sensor->u.acceleration.y,
                 sensor->u.acceleration.z);
        _hwSensorClient_send(cl, (uint8_t*)buffer, strlen(buffer));
    }

    if (_hwSensorClient_enabled(cl, ANDROID_SENSOR_MAGNETIC_FIELD)) {
        sensor = &hw->sensors[ANDROID_SENSOR_MAGNETIC_FIELD];
        /* NOTE: sensors HAL expects "magnetic", not "magnetic-field" name here. */
        snprintf(buffer, sizeof buffer, "magnetic:%g:%g:%g",
                 sensor->u.magnetic.x,
                 sensor->u.magnetic.y,
                 sensor->u.magnetic.z);
        _hwSensorClient_send(cl, (uint8_t*)buffer, strlen(buffer));
    }

    if (_hwSensorClient_enabled(cl, ANDROID_SENSOR_ORIENTATION)) {
        sensor = &hw->sensors[ANDROID_SENSOR_ORIENTATION];
        snprintf(buffer, sizeof buffer, "orientation:%g:%g:%g",
                 sensor->u.orientation.azimuth,
                 sensor->u.orientation.pitch,
                 sensor->u.orientation.roll);
        _hwSensorClient_send(cl, (uint8_t*)buffer, strlen(buffer));
    }

    if (_hwSensorClient_enabled(cl, ANDROID_SENSOR_TEMPERATURE)) {
        sensor = &hw->sensors[ANDROID_SENSOR_TEMPERATURE];
        snprintf(buffer, sizeof buffer, "temperature:%g",
                 sensor->u.temperature.celsius);
        _hwSensorClient_send(cl, (uint8_t*)buffer, strlen(buffer));
    }

    if (_hwSensorClient_enabled(cl, ANDROID_SENSOR_PROXIMITY)) {
        sensor = &hw->sensors[ANDROID_SENSOR_PROXIMITY];
        snprintf(buffer, sizeof buffer, "proximity:%g",
                 sensor->u.proximity.value);
        _hwSensorClient_send(cl, (uint8_t*) buffer, strlen(buffer));
    }

    now_ns = qemu_get_clock_ns(vm_clock);

    snprintf(buffer, sizeof buffer, "sync:%" PRId64, now_ns/1000);
    _hwSensorClient_send(cl, (uint8_t*)buffer, strlen(buffer));

    /* rearm timer, use a minimum delay of 20 ms, just to
     * be safe.
     */
    if (mask == 0)
        return;

    if (delay < 20)
        delay = 20;

    delay *= 1000000LL;  /* convert to nanoseconds */
    qemu_mod_timer(cl->timer, now_ns + delay);
}

/* handle incoming messages from the HAL module */
static void
_hwSensorClient_receive( HwSensorClient*  cl, uint8_t*  msg, int  msglen )
{
    HwSensors*  hw = cl->sensors;

    D("%s: '%.*s'", __FUNCTION__, msglen, msg);

    /* "list-sensors" is used to get an integer bit map of
     * available emulated sensors. We compute the mask from the
     * current hardware configuration.
     */
    if (msglen == 12 && !memcmp(msg, "list-sensors", 12)) {
        char  buff[12];
        int   mask = 0;
        int   nn;

        for (nn = 0; nn < MAX_SENSORS; nn++) {
            if (hw->sensors[nn].enabled)
                mask |= (1 << nn);
        }

        snprintf(buff, sizeof buff, "%d", mask);
        _hwSensorClient_send(cl, (const uint8_t*)buff, strlen(buff));
        return;
    }

    /* "wake" is a special message that must be sent back through
     * the channel. It is used to exit a blocking read.
     */
    if (msglen == 4 && !memcmp(msg, "wake", 4)) {
        _hwSensorClient_send(cl, (const uint8_t*)"wake", 4);
        return;
    }

    /* "set-delay:<delay>" is used to set the delay in milliseconds
     * between sensor events
     */
    if (msglen > 10 && !memcmp(msg, "set-delay:", 10)) {
        cl->delay_ms = atoi((const char*)msg+10);
        if (cl->enabledMask != 0)
            _hwSensorClient_tick(cl);

        return;
    }

    /* "set:<name>:<state>" is used to enable/disable a given
     * sensor. <state> must be 0 or 1
     */
    if (msglen > 4 && !memcmp(msg, "set:", 4)) {
        char*  q;
        int    id, enabled, oldEnabledMask = cl->enabledMask;
        msg += 4;
        q    = strchr((char*)msg, ':');
        if (q == NULL) {  /* should not happen */
            D("%s: ignore bad 'set' command", __FUNCTION__);
            return;
        }
        *q++ = 0;

        id = _sensorIdFromName((const char*)msg);
        if (id < 0 || id >= MAX_SENSORS) {
            D("%s: ignore unknown sensor name '%s'", __FUNCTION__, msg);
            return;
        }

        if (!hw->sensors[id].enabled) {
            D("%s: trying to set disabled %s sensor", __FUNCTION__, msg);
            return;
        }
        enabled = (q[0] == '1');

        if (enabled)
            cl->enabledMask |= (1 << id);
        else
            cl->enabledMask &= ~(1 << id);

        if (cl->enabledMask != oldEnabledMask) {
            D("%s: %s %s sensor", __FUNCTION__,
                (cl->enabledMask & (1 << id))  ? "enabling" : "disabling",  msg);
        }

        /* If emulating device is connected update sensor state there too. */
        /*if (hw->sensors_port != NULL && sensors_port_is_connected(hw->sensors_port)) {
            if (enabled) {
                sensors_port_enable_sensor(hw->sensors_port, (const char*)msg);
            } else {
                sensors_port_disable_sensor(hw->sensors_port, (const char*)msg);
            }
        }*/

        _hwSensorClient_tick(cl);
        return;
    }

    D("%s: ignoring unknown query", __FUNCTION__);
}
#if (0)
/* Saves sensor-specific client data to snapshot */
static void
_hwSensorClient_save( QEMUFile*  f, QemudClient*  client, void*  opaque  )
{
    HwSensorClient* sc = opaque;

    qemu_put_be32(f, sc->delay_ms);
    qemu_put_be32(f, sc->enabledMask);
    qemu_put_timer(f, sc->timer);
}

/* Loads sensor-specific client data from snapshot */
static int
_hwSensorClient_load( QEMUFile*  f, QemudClient*  client, void*  opaque  )
{
    HwSensorClient* sc = opaque;

    sc->delay_ms = qemu_get_be32(f);
    sc->enabledMask = qemu_get_be32(f);
    qemu_get_timer(f, sc->timer);

    return 0;
}
#endif

static QemudClient*
_hwSensors_connect( void*  opaque,
                    QemudService*  service,
                    int  channel,
                    const char* client_param )
{
    HwSensors*       sensors = opaque;
    HwSensorClient*  cl      = _hwSensorClient_new(sensors);
    QemudClient*     client  = qemud_client_new(service, channel, client_param, cl,
                                                _hwSensorClient_recv,
                                                _hwSensorClient_close,
                                                NULL,
                                                NULL );
    qemud_client_set_framing(client, 1);
    cl->client = client;

    return client;
}

/* change the value of the emulated sensor vector */
static void
_hwSensors_setSensorValue( HwSensors*  h, int sensor_id, float a, float b, float c )
{
    Sensor* s = &h->sensors[sensor_id];

    s->u.value.a = a;
    s->u.value.b = b;
    s->u.value.c = c;
}

#if (0)
/* Saves available sensors to allow checking availability when loaded.
 */
static void
_hwSensors_save( QEMUFile*  f, QemudService*  sv, void*  opaque)
{
    HwSensors* h = opaque;

    // number of sensors
    qemu_put_be32(f, MAX_SENSORS);
    AndroidSensor i;
    for (i = 0 ; i < MAX_SENSORS; i++) {
        Sensor* s = &h->sensors[i];
        qemu_put_be32(f, s->enabled);

        /* this switch ensures that a warning is raised when a new sensor is
         * added and is not added here as well.
         */
        switch (i) {
        case ANDROID_SENSOR_ACCELERATION:
            qemu_put_float(f, s->u.acceleration.x);
            qemu_put_float(f, s->u.acceleration.y);
            qemu_put_float(f, s->u.acceleration.z);
            break;
        case ANDROID_SENSOR_MAGNETIC_FIELD:
            qemu_put_float(f, s->u.magnetic.x);
            qemu_put_float(f, s->u.magnetic.y);
            qemu_put_float(f, s->u.magnetic.z);
            break;
        case ANDROID_SENSOR_ORIENTATION:
            qemu_put_float(f, s->u.orientation.azimuth);
            qemu_put_float(f, s->u.orientation.pitch);
            qemu_put_float(f, s->u.orientation.roll);
            break;
        case ANDROID_SENSOR_TEMPERATURE:
            qemu_put_float(f, s->u.temperature.celsius);
            break;
        case ANDROID_SENSOR_PROXIMITY:
            qemu_put_float(f, s->u.proximity.value);
            break;
        case MAX_SENSORS:
            break;
        }
    }
}


static int
_hwSensors_load( QEMUFile*  f, QemudService*  s, void*  opaque)
{
    HwSensors* h = opaque;

    /* check number of sensors */
    int32_t num_sensors = qemu_get_be32(f);
    if (num_sensors > MAX_SENSORS) {
        D("%s: cannot load: snapshot requires %d sensors, %d available\n",
          __FUNCTION__, num_sensors, MAX_SENSORS);
        return -EIO;
    }

    /* load sensor state */
    AndroidSensor i;
    for (i = 0 ; i < num_sensors; i++) {
        Sensor* s = &h->sensors[i];
        s->enabled = qemu_get_be32(f);

        /* this switch ensures that a warning is raised when a new sensor is
         * added and is not added here as well.
         */
        switch (i) {
        case ANDROID_SENSOR_ACCELERATION:
            s->u.acceleration.x = qemu_get_float(f);
            s->u.acceleration.y = qemu_get_float(f);
            s->u.acceleration.z = qemu_get_float(f);
            break;
        case ANDROID_SENSOR_MAGNETIC_FIELD:
            s->u.magnetic.x = qemu_get_float(f);
            s->u.magnetic.y = qemu_get_float(f);
            s->u.magnetic.z = qemu_get_float(f);
            break;
        case ANDROID_SENSOR_ORIENTATION:
            s->u.orientation.azimuth = qemu_get_float(f);
            s->u.orientation.pitch   = qemu_get_float(f);
            s->u.orientation.roll    = qemu_get_float(f);
            break;
        case ANDROID_SENSOR_TEMPERATURE:
            s->u.temperature.celsius = qemu_get_float(f);
            break;
        case ANDROID_SENSOR_PROXIMITY:
            s->u.proximity.value = qemu_get_float(f);
            break;
        case MAX_SENSORS:
            break;
        }
    }

    /* The following is necessary when we resume a snaphost
     * created by an older version of the emulator that provided
     * less hardware sensors.
     */
    for ( ; i < MAX_SENSORS; i++ ) {
        h->sensors[i].enabled = 0;
    }

    return 0;
}
#endif

/* change the emulated proximity */
static void
_hwSensors_setProximity( HwSensors*  h, float value )
{
    Sensor*  s = &h->sensors[ANDROID_SENSOR_PROXIMITY];
    s->u.proximity.value = value;
}

/* change the coarse orientation (landscape/portrait) of the emulated device */
static void
_hwSensors_setCoarseOrientation( HwSensors*  h, AndroidCoarseOrientation  orient )
{
    /* The Android framework computes the orientation by looking at
     * the accelerometer sensor (*not* the orientation sensor !)
     *
     * That's because the gravity is a constant 9.81 vector that
     * can be determined quite easily.
     *
     * Also, for some reason, the framework code considers that the phone should
     * be inclined by 30 degrees along the phone's X axis to be considered
     * in its ideal "vertical" position
     *
     * If the phone is completely vertical, rotating it will not do anything !
     */
    const double  g      = 9.81;
    const double  angle  = 20.0;
    const double  cos_angle = cos(angle/M_PI);
    const double  sin_angle = sin(angle/M_PI);

    switch (orient) {
    case ANDROID_COARSE_PORTRAIT:
        _hwSensors_setSensorValue( h, ANDROID_SENSOR_ACCELERATION, 0., g*cos_angle, g*sin_angle );
        break;

    case ANDROID_COARSE_LANDSCAPE:
        _hwSensors_setSensorValue( h, ANDROID_SENSOR_ACCELERATION, g*cos_angle, 0., g*sin_angle );
        break;
    default:
        ;
    }
}

#define SENSORS_HACK_HACK_HACK
#ifdef SENSORS_HACK_HACK_HACK
struct __sensor_hack {
 bool hw_accelerometer;
 bool hw_sensors_proximity;
 bool hw_sensors_magnetic_field;
 bool hw_sensors_orientation;
 bool hw_sensors_temperature;
};

struct __sensor_hack __hack_hack = {true, true, true, true, true};
struct __sensor_hack* android_hw = &__hack_hack;
#endif

/* initialize the sensors state */
static void
_hwSensors_init( HwSensors*  h )
{
    /* Try to see if there is a device attached that can be used for
     * sensor emulation. */
    h->sensors_port = NULL; //sensors_port_create(h);
    if (h->sensors_port == NULL) {
        V("Realistic sensor emulation is not available, since the remote controller is not accessible:\n %s",
          strerror(errno));
    }

    h->service = qemud_service_register("sensors", 0, h, _hwSensors_connect,
                                        NULL, NULL);

    if (android_hw->hw_accelerometer) {
        h->sensors[ANDROID_SENSOR_ACCELERATION].enabled = 1;
    }

    if (android_hw->hw_sensors_proximity) {
        h->sensors[ANDROID_SENSOR_PROXIMITY].enabled = 1;
    }

    if (android_hw->hw_sensors_magnetic_field) {
        h->sensors[ANDROID_SENSOR_MAGNETIC_FIELD].enabled = 1;
    }

    if (android_hw->hw_sensors_orientation) {
        h->sensors[ANDROID_SENSOR_ORIENTATION].enabled = 1;
    }

    if (android_hw->hw_sensors_temperature) {
        h->sensors[ANDROID_SENSOR_TEMPERATURE].enabled = 1;
    }

    if (h->sensors_port != NULL) {
        /* Init sensors on the attached device. */
        //sensors_port_init_sensors(h->sensors_port);
    }

    /* XXX: TODO: Add other tests when we add the corresponding
        * properties to hardware-properties.ini et al. */

    _hwSensors_setCoarseOrientation(h, ANDROID_COARSE_PORTRAIT);
    _hwSensors_setProximity(h, 1);
}

static HwSensors    _sensorsState[1];

void
android_hw_sensors_init( void )
{
    HwSensors*  hw = _sensorsState;

    if (hw->service == NULL) {
        _hwSensors_init(hw);
        D("%s: sensors qemud service initialized", __FUNCTION__);
    }
}

/* change the coarse orientation value */
extern void
android_sensors_set_coarse_orientation( AndroidCoarseOrientation  orient )
{
    android_hw_sensors_init();
    _hwSensors_setCoarseOrientation(_sensorsState, orient);
}

/* Get sensor name from sensor id */
extern const char*
android_sensors_get_name_from_id( int sensor_id )
{
    if (sensor_id < 0 || sensor_id >= MAX_SENSORS)
        return NULL;

    return _sensorNameFromId(sensor_id);
}

/* Get sensor id from sensor name */
extern int
android_sensors_get_id_from_name( char* sensorname )
{
    HwSensors* hw = _sensorsState;

    if (sensorname == NULL)
        return SENSOR_STATUS_UNKNOWN;

    int id = _sensorIdFromName(sensorname);

    if (id < 0 || id >= MAX_SENSORS)
        return SENSOR_STATUS_UNKNOWN;

    if (hw->service != NULL) {
        if (! hw->sensors[id].enabled)
            return SENSOR_STATUS_DISABLED;
    } else
        return SENSOR_STATUS_NO_SERVICE;

    return id;
}

/* Interface of reading the data for all sensors */
extern int
android_sensors_get( int sensor_id, float* a, float* b, float* c )
{
    HwSensors* hw = _sensorsState;

    *a = 0;
    *b = 0;
    *c = 0;

    if (sensor_id < 0 || sensor_id >= MAX_SENSORS)
        return SENSOR_STATUS_UNKNOWN;

    Sensor* sensor = &hw->sensors[sensor_id];
    if (hw->service != NULL) {
        if (! sensor->enabled)
            return SENSOR_STATUS_DISABLED;
    } else
        return SENSOR_STATUS_NO_SERVICE;

    *a = sensor->u.value.a;
    *b = sensor->u.value.b;
    *c = sensor->u.value.c;

    return SENSOR_STATUS_OK;
}

/* Interface of setting the data for all sensors */
extern int
android_sensors_set( int sensor_id, float a, float b, float c )
{
    HwSensors* hw = _sensorsState;

    if (sensor_id < 0 || sensor_id >= MAX_SENSORS)
        return SENSOR_STATUS_UNKNOWN;

    if (hw->service != NULL) {
        if (! hw->sensors[sensor_id].enabled)
            return SENSOR_STATUS_DISABLED;
    } else
        return SENSOR_STATUS_NO_SERVICE;

    _hwSensors_setSensorValue(hw, sensor_id, a, b, c);

    return SENSOR_STATUS_OK;
}

/* Get Sensor from sensor id */
extern uint8_t
android_sensors_get_sensor_status( int sensor_id )
{
    HwSensors* hw = _sensorsState;

    if (sensor_id < 0 || sensor_id >= MAX_SENSORS)
        return SENSOR_STATUS_UNKNOWN;

    return hw->sensors[sensor_id].enabled;
}
