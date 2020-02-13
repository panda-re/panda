#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "hw/sysbus.h"
#include <Python.h>

#ifdef TARGET_ARM
#include "target/arm/cpu.h"
#endif


#define TYPE_AVATAR_PYPERIPHERAL "avatar-pyperipheral"
#define AVATAR_PYPERIPHERAL(obj) OBJECT_CHECK(AvatarPyPeripheralState, (obj), TYPE_AVATAR_PYPERIPHERAL)

typedef struct AvatarPyPeripheralState {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    uint64_t address;
    uint32_t size;
    uint64_t request_id;
    char *python_file;
    char *python_class;
    char *python_kwargs;
    char *name;
    PyObject *pyperipheral;
    qemu_irq irq;
} AvatarPyPeripheralState;



static uint64_t avatar_pyperipheral_read(void *opaque, hwaddr offset,
                           unsigned size)
{
    PyObject *pRes;
    uint64_t res;
    AvatarPyPeripheralState *s = (AvatarPyPeripheralState *) opaque;
    
    pRes = PyObject_CallMethod(s->pyperipheral, (char *) "read_memory", 
            (char *) "li", s->address+offset, size); //pArgs);

    if (pRes == NULL){
        fprintf(stderr, "[Avatar-PyPeripheral] Memory Read failed\n");
        PyErr_Print();
        exit(-1);
    }

    res =  PyInt_AsUnsignedLongMask(pRes);

    Py_DECREF(pRes);
    //TODO Evaluate Response
    return res;
}


static void avatar_pyperipheral_write(void *opaque, hwaddr offset,
                        uint64_t value, unsigned size)
{
    PyObject *pRes;
    AvatarPyPeripheralState *s = (AvatarPyPeripheralState *) opaque;
    
    pRes = PyObject_CallMethod(s->pyperipheral, (char *) "write_memory",
        (char *)"lil", s->address+offset, size, value);
    if (pRes == NULL){
        fprintf(stderr, "[Avatar-PyPeripheral] Memory Write failed\n");
        PyErr_Print();
        exit(-1);
    }

    Py_DECREF(pRes);
}

static const MemoryRegionOps avatar_pyperipheral_ops = {
    .read = avatar_pyperipheral_read,
    .write = avatar_pyperipheral_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static Property avatar_pyperipheral_properties[] = {
    DEFINE_PROP_UINT64("address", AvatarPyPeripheralState, address, 0x101f1000),
    DEFINE_PROP_UINT32("size", AvatarPyPeripheralState, size, 0x100),
    DEFINE_PROP_STRING("python_file", AvatarPyPeripheralState, python_file),
    DEFINE_PROP_STRING("python_class", AvatarPyPeripheralState, python_class),
    DEFINE_PROP_STRING("python_kwargs", AvatarPyPeripheralState, python_kwargs),
    DEFINE_PROP_STRING("name", AvatarPyPeripheralState, name),
    DEFINE_PROP_END_OF_LIST(),
};


static void avatar_pyperipheral_realize(DeviceState *dev, Error **errp)
{
    PyObject *pFile, *pModule, *pModuleDict, *pPeriphClass, *pArgs, *pKwargs,
             *pAst, *pEval, *pEvalArgs;
    AvatarPyPeripheralState *s = AVATAR_PYPERIPHERAL(dev);

    Py_Initialize();
    pFile = PyString_FromString(s->python_file);

    pModule = PyImport_Import(pFile);
    if (pModule == NULL){
        fprintf(stderr, "[Avatar-PyPeripheral] Couldn't import PythonFile:\n");
        PyErr_Print();
        exit(-1);
    }

    pModuleDict = PyModule_GetDict(pModule);

    pPeriphClass = PyDict_GetItemString(pModuleDict, s->python_class);

    if (!PyCallable_Check(pPeriphClass)){
        fprintf(stderr, "[Avatar-PyPeripheral] Couldn't instantiate peripheral class\n");
        PyErr_Print();
        exit(-1);
    }

    pArgs = Py_BuildValue("sli", s->name, s->address, s->size);

    //Create kwargs from s->pyperipheral kwargs, using ast and literal_eval
    if (s->python_kwargs == NULL){
        pKwargs =  PyDict_New(); //TODO Kwargs parsing
    }
    else{
        pAst = PyImport_ImportModule("ast");
        pEval = PyObject_GetAttrString(pAst, "literal_eval");
        pEvalArgs = Py_BuildValue("(s)", s->python_kwargs);
        pKwargs = PyObject_CallObject(pEval, pEvalArgs);

        Py_DECREF(pAst);
        Py_DECREF(pEval);
        Py_DECREF(pEvalArgs);
    }
    if (pKwargs == NULL){
        fprintf(stderr, "[Avatar-PyPeripheral] Failed to create kwargs-dict:\n");
        PyErr_Print();
        exit(-1);
    }
    

    s->pyperipheral = PyObject_Call(pPeriphClass, pArgs, pKwargs); 

    if (s->pyperipheral == NULL){
        fprintf(stderr, "[Avatar-PyPeripheral] Couldn't instantiate peripheral object\n");
        PyErr_Print();
        exit(-1);
    }
    Py_DECREF(pFile);
    Py_DECREF(pModule);
    Py_DECREF(pArgs);
    Py_DECREF(pKwargs);




    SysBusDevice *sbd = SYS_BUS_DEVICE(s);
    memory_region_init_io(&s->iomem, OBJECT(s), &avatar_pyperipheral_ops, s, "avatar-pyperipheral", s->size);
    sysbus_init_mmio(sbd, &s->iomem);
    sysbus_init_irq(sbd, &s->irq);


}

static void avatar_pyperipheral_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);

    dc->realize = avatar_pyperipheral_realize;
    dc->props = avatar_pyperipheral_properties;
}

static const TypeInfo avatar_pyperipheral_arm_info = {
    .name          = TYPE_AVATAR_PYPERIPHERAL,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AvatarPyPeripheralState),
    //.instance_init = avatar_pyperipheral_init,
    .class_init    = avatar_pyperipheral_class_init,
};

static void avatar_pyperipheral_register_types(void)
{
    type_register_static(&avatar_pyperipheral_arm_info);
}

type_init(avatar_pyperipheral_register_types)
