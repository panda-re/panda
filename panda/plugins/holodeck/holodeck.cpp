/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Andrew Fasano          andrew.fasano@ll.mit.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

// Verbose logging flag
//#define HOLODECK_LOG

#include "panda/plugin.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
#include "include/qemu/option.h"
#include "include/qemu/config-file.h"
}

#include "yaml-cpp/yaml.h"
#include "holodeck.h"
#include <iostream>

char dtbfile[32];
std::vector<Device> device_list;

// Given a model, handle its write
 void save_write(Model &m, uint64_t *val) {
    switch (m.writePolicy) {
        case WriteIgnore:
            return;
            break;
        case WriteStoreBuffer:
            // Dump if it's too long or we're getting a new log
            if (m.obuf.buf->length() > 160 || (char)(*val) == '[') {
                fprintf(stderr, "%s\n", m.obuf.buf->c_str());
                m.obuf.buf->erase();
            }

            // If newline or null byte, dump and clear buffer
            if ((char)(*val) == '\n') {
                fprintf(stderr, "%s", m.obuf.buf->c_str());
                m.obuf.buf->erase();

            } else { // append to buffer
                m.obuf.buf->append(1, (char)*val);
            }



            break;

        case WriteLast:
            // Store last char
            m.obyte.byte = (char)*val;
            break;

        default:
            assert(0);
            return;

    }
}

// Given a model, get the next value and update any internal state
unsigned int _generate_value(Model &m) {
    switch (m.type) {
        case ModelConstant:
            return m.c.value;
            break;
        case ModelSequence:
           if (m.s.offset >= (m.s.values)->size()) {
              if (m.readPolicy == ReadRepeat) {
                   m.s.offset=0;
              }else{
                  fprintf(stderr, "Ran out of sequence (len %d) and unit_read_polic=abort\n",
                          m.s.offset-1);
                  assert(0);
              }
           }
           if ((m.s.offset) < (m.s.values)->size()) {
               m.s.offset++;
               return (*m.s.values)[m.s.offset-1];
           } else {
               return 0;
           }
            break;
        case ModelRandomUniform:
            return (*m.s.values)[rand() % (m.s.values->size())];
            break;

        case ModelOutput:
          fprintf(stderr, "Reading from output device. Returning 0\n");
          return 0;
          //fprintf(stderr, "Reading from output device. Enter value to return >\n");
          //return getchar();

        default:
            assert(0);
            return 0;
    }

}

// Given a device and an offset, find the matching model and generate_value on it
bool _generate_value(Device &dev, unsigned int offset, unsigned int *result) {
    for (auto &model : dev.models) {
        if (model.offset==offset) {
            *result = _generate_value(model);
            return true;
        }
    }

    //fprintf(stderr, "Error: [holodeck] couldn't find model in %s at offset 0x%x to generate value\n", dev.name.c_str(), offset);
    return false;
}

unsigned int generate_value(std::vector<Device> devices, unsigned int address) {
    // Do we handle it? If so
    for (auto &dev : devices) {
        if (address >= dev.start && address < (dev.start+dev.length)) {
            // Found device, now generate respond
            //fprintf(stderr, "\nInfo: [holodeck] trying device %s\n", dev.name.c_str());

            unsigned int result;
            if (_generate_value(dev, address-dev.start, &result)) {
                return result;
            }else {
                return 0xFFFFFFFF; // TODO: instead of returning 0xFFFFFFFF, just fail?
            }
        }
    }


    fprintf(stderr, "Error: [holodeck] couldn't find any config to generate value at 0x%x. Aborting\n", address);
    assert(0);
    //panda_unload_plugins();
    //fprintf(stderr, "Error: [holodeck] couldn't find any config to generate value at 0x%x. Suspending execution\n", address);
    //vm_stop(RUN_STATE_PAUSED);
    //qemu_system_suspend();
}

//Parse a yaml tree, output in devices vector
bool parse_devices(YAML::Node &devices_y, std::vector<Device> &devices) {
    // For each device
    for(auto device : devices_y) {
       std::string name = device.first.as<std::string>();
       Device d;

       d.name = name;
       assert(device.second["start"]);
       assert(device.second["length"]);
       d.start = device.second["start"].as<unsigned int>();
       d.length = device.second["length"].as<unsigned int>();

       std::vector<Model> models;

       for (auto props : device.second["models"]) {
           Model m;
           m.offset = props.first.as<unsigned int>();

           std::string model_name = props.second["type"].as<std::string>();

           // Uninit read policy
           if (props.second["uninit_read_policy"] &&
              props.second["uninit_read_policy"].as<std::string>() == "repeat") {
               m.readPolicy=ReadRepeat; // repeat loop
           }else{
               m.readPolicy=ReadAbort; // Default abort
           }

           // Write policy
           if (props.second["write_policy"] &&
              props.second["write_policy"].as<std::string>() == "ignore") {
               m.writePolicy=WriteIgnore;
           }else if (props.second["write_policy"] &&
               props.second["write_policy"].as<std::string>() == "store_buffer") {
               m.writePolicy=WriteStoreBuffer;
           }else{
               m.writePolicy=WriteLast;
           }


           if (model_name == "constant") {
               m.type = ModelConstant;
           } else if (model_name == "sequence") {
               m.type = ModelSequence;
           } else if (model_name == "random-uniform") {
               m.type = ModelRandomUniform;
           } else if (model_name == "output") {
               m.type = ModelOutput;
           }else{
               fprintf(stderr, "Error: [holodeck] found unknown model type %s\n", model_name.c_str());
               return false;
           }

           switch(m.type) {
               case ModelConstant:
                   Constant c;
                   assert(props.second["reads"]);
                   c.value = props.second["reads"].as<unsigned int>();
                   m.c = c;
                   break;

               case ModelSequence: {
                   Sequence seq;

                   seq.offset = 0;
                   seq.values = new std::vector<unsigned int>;

                   assert(props.second["reads"]);
                   const YAML::Node& seqvals = props.second["reads"];
                   for(unsigned i=0;i<seqvals.size();i++) {
                       unsigned int intval = seqvals[i].as<unsigned int>();
                       (*seq.values).push_back(intval);
                   }
                   m.s = seq;
                   }
                   break;

               case ModelRandomUniform: {
                   RandomUniform rnd;

                   rnd.rndseed = 0;
                   rnd.values = new std::vector<unsigned int>;

                   assert(props.second["reads"]);
                   const YAML::Node& seqvals = props.second["reads"];
                   for(unsigned i=0;i<seqvals.size();i++) {
                       int intval = seqvals[i].as<unsigned int>();
                       (*rnd.values).push_back(intval);
                   }
                   m.r = rnd;
                   }
                   break;

               case ModelOutput:  // Initialize output
                   m.obuf.buf = new std::string;
                   break;
           }

           models.push_back(m);
       }

       d.models = models;
       devices.push_back(d);
    }

    return true;
}

// Dump state of devices, Takes list by reference because dumping modifies internal model states
void dump_devices(std::vector<Device> &devices) {
    // Done parsing devices. Test print all devices
    for (auto &dev : devices) {
        printf("Device %s starts at 0x%x and has %lu models:\n", dev.name.c_str(), dev.start, dev.models.size());
        for (auto &model : dev.models) {
            printf("\tOffset 0x%x:\n", model.offset);
            switch (model.type) {
                case ModelConstant:
                    printf("\t\tConstant: %d\n", model.c.value);
                    break;
                case ModelSequence: {
                    printf("\t\tSequence at offset %d. Values: ", model.s.offset);
                    for (auto &i : *model.s.values) {
                            std::cout << i << ", ";
                    }
                    printf("\n");
                    }

                    break;
                case ModelRandomUniform: {
                    printf("\t\tUniformRandom seed=%d. Values: ", model.r.rndseed);
                    for (auto &i : *model.r.values) {
                            std::cout << i << ", ";
                    }
                    printf("\n");
                    }
                    break;
               case ModelOutput: 
                   fprintf(stderr, "Can't write to output model\n");
                   assert(0);
                   break;
            }

            /*
            printf("\t\tSample values:\t");
            for(int j=0;j<10;j++) 
                printf(" %u,", _generate_value(dev, model.offset));
            printf("\n");
            */
        }
    }
}

void cleanup_devices(std::vector<Device> &devices) {
    //Cleanup
    for (auto &dev : devices) {
        // Delete allocated vectors* in models where necessary
        for (auto &model : dev.models) {
            if (model.type == ModelSequence) {
                delete model.s.values;
            } else if (model.type == ModelRandomUniform) {
                delete model.r.values;
            }

            if (model.writePolicy == WriteStoreBuffer) {
                delete model.obuf.buf;
            }
        }

    }
}

bool is_ascii(char x) {
    return (x > 0x20) && (x < 0x7e);
}
void saw_unassigned_io_write(CPUState *env, target_ulong pc, hwaddr addr, 
                            uint32_t size, uint64_t *val) {
    // Find device
    for (auto &dev : device_list) {
        unsigned int offset = addr - dev.start;
        if (addr >= dev.start && addr < (dev.start+dev.length)) {
            // Now find model
            for (auto &model : dev.models) {
                if (model.offset==offset) {
                    save_write(model, val);
                    return;
                }
            }
#ifdef HOLODECK_LOG
            fprintf(stderr, "INFO: [holodeck] ignoring unassigned write to modeled "
                   "device at 0x%x because offset 0xl%x is unmodeled\n\t "
                   "written value: %lx\n", dev.start, offset, *val);
#endif
        }
    }

    // Else no model, ignore write

#ifdef HOLODECK_LOG
    unsigned int mask = 0x000000FF;
    char c0 = (char)((*val)&mask);
    char c1 = (char)((*val>>8)&mask);
    char c2 = (char)((*val>>16)&mask);
    char c3 = (char)((*val>>24)&mask);

    // If at least first char is ascii and rest are ascii or null, print
    if (is_ascii(c0) &&
        (is_ascii(c1) || c1 == 0) &&
        (is_ascii(c2) || c2 == 0) &&
        (is_ascii(c2) || c3 == 0)) {
        fprintf(stderr, "INFO: [holodeck] unassigned write to 0x%lx ascii: %c%c%c%c\n", addr,c0, c1, c2, c3);
    }else{
        fprintf(stderr, "INFO: [holodeck] ignoring unassigned write to unmodeled "
                "0x%lx value: %lx\n", addr, *val);
    }
#endif
}

void saw_unassigned_io_read(CPUState *env, target_ulong pc, hwaddr addr, 
                            uint32_t size, uint64_t *val) {

#ifdef HOLODECK_LOG
    fprintf(stderr, "INFO: [holodeck] unassigned read to 0x%lx of size %x.. ", addr, size);
#endif
    uint64_t v= generate_value(device_list, addr);
#ifdef HOLODECK_LOG
    fprintf(stderr, "\treturning 0x%lx\n", v);
#endif
    *val = v;
}


bool init_plugin(void *self) {
#ifdef TARGET_ARM
    panda_arg_list *args = panda_get_args("holodeck");
    const char *config_path = NULL;
    if (args != NULL) {
         config_path = panda_parse_string_req(args, "config", "holodeck config file");
    }
    assert(config_path != NULL);

    // Setup machine type
    const char *optarg;
    QemuOpts *opts;

    // Warn if a machine type was already specified
    opts = qemu_find_opts_singleton("machine");
    optarg = qemu_opt_get(opts, "type");
    if (optarg) {
        fprintf(stderr, "Warning: [holodeck] Machine type was set to '%s' but holodeck plugin is using machine rehosting\n", optarg);
    }

    // Set machine type to 'rehosting' and specify parameters from config
    Error* error_abort;
    qemu_opts_set(qemu_find_opts("machine"), 0, "type", "rehosting",
                                          &error_abort);

    YAML::Node config = YAML::LoadFile(config_path);

    // Parse machine from config
    assert(config["machine"]);
    YAML::Node machine_y = config["machine"];

    assert(machine_y["peripherals"]);
    std::stringstream memmap;
    for (auto peripheral : machine_y["peripherals"]) {
        std::string pname = peripheral.first.as<std::string>();
        std::string pvalue = peripheral.second.as<std::string>();
        memmap << pname << " " << pvalue << ";";
    }

    assert(machine_y["board_id"]);
    int board_id = machine_y["board_id"].as<int>();
    std::string board_id_s = std::to_string(board_id);

    qemu_opts_set(qemu_find_opts("machine"), 0, "mem-map", memmap.str().c_str(),
                                          &error_abort);

    qemu_opts_set(qemu_find_opts("machine"), 0, "board-id", board_id_s.c_str(),
                                          &error_abort);

    // Parse DTB from config (final version with patches)
    assert(machine_y["dtb"]);

    // Note: the dtb must be single quoted line, not what's output by python
    YAML::Binary binary = config["machine"]["dtb"].as<YAML::Binary>();

    const unsigned char * data = binary.data();
    std::size_t size = binary.size();

    // Write DTB to disk
    strncpy(dtbfile, "/tmp/holodeck-XXXXXXXX",32);
    assert(mkstemp(dtbfile) != NULL);
    printf("DTB at %s\n", dtbfile);

    FILE *f = fopen(dtbfile, "wb");
    if (f==NULL) {
        perror("Failed to make tempfile");
        assert(0);
    }

    fwrite(data, size, 1, f);
    fclose(f);

    // Pass tempfile path to qemu
    qemu_opts_set(qemu_find_opts("machine"), 0, "dtb", dtbfile,
                   &error_abort);


    // Parse devices from config
    assert(config["devices"]);
    YAML::Node devices_y = config["devices"];

    if (!parse_devices(devices_y, device_list)) {
        fprintf(stderr, "Error: [holodeck] Couldn't parse input config. Aborting\n");
        assert(0);
    }

#ifdef HOLODECK_LOG
    fprintf(stderr, "INFO: [holodeck] Parsed input config!\n");
    //dump_devices(device_list);
#endif

    // Register callbacks
    panda_cb pcb;
    pcb.unassigned_io_read = saw_unassigned_io_read;
    panda_register_callback(self, PANDA_CB_UNASSIGNED_IO_READ, pcb);

    pcb.unassigned_io_write = saw_unassigned_io_write;
    panda_register_callback(self, PANDA_CB_UNASSIGNED_IO_WRITE, pcb);

    return true;
#else
    fprintf(stderr, "Error: [holodeck] Holodeck is unsupported on this architecture\n");
    return false;
#endif
}

void uninit_plugin(void *self) {
#ifdef TARGET_ARM
    // TODO: this will not run if qemu fails early?
#ifdef HOLODECK_LOG
    fprintf(stderr, "INFO: [holodeck] cleaning up\n");
#endif

    if (dtbfile != NULL)
        unlink(dtbfile);

    for (auto &dev : device_list) {
        for (auto &model : dev.models) {
            if (model.writePolicy == WriteStoreBuffer) {
                // Dump log before quitting
                fprintf(stderr, "%s\n", (*model.obuf.buf).c_str());
            }
        }
    }

    if (device_list.size() > 0 )
        cleanup_devices(device_list);
#endif

}
