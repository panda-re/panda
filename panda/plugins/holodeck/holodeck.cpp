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

#include "panda/plugin.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

}

#include "yaml-cpp/yaml.h"
#include "holodeck.h"
#include <iostream>

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
        default:
            assert(0);
            return 0;
    }

}

// Given a device and an offset, find the matching model and generate_value on it
unsigned int _generate_value(Device &dev, unsigned int offset) {
    for (auto &model : dev.models) {
        if (model.offset==offset) {
            return _generate_value(model);
        }
    }

    printf("Couldn't find config to generate value. Aborting\n");
    assert(0);
}

unsigned int generate_value(std::vector<Device> devices, unsigned int address) {
    // Do we handle it? If so
    for (auto &dev : devices) {
        if (address > dev.start && address < (dev.start+dev.length)) {
            // Found device, now generate respond
            return _generate_value(dev, address-dev.start);
        }
    }

    printf("Couldn't find config to generate value. Aborting\n");
    assert(0);
}

//Parse a yaml tree, output in devices vector
bool parse_devices(YAML::Node &devices_y, std::vector<Device> &devices) {
    // For each device
    for(auto device : devices_y) {
       std::string name = device.first.as<std::string>();
       Device d;

       d.name = name;
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
           }else{
               m.writePolicy=WriteLast;
           }


           if (model_name == "constant") {
               m.type = ModelConstant;
           } else if (model_name == "sequence") {
               m.type = ModelSequence;
           } else if (model_name == "random-uniform") {
               m.type = ModelRandomUniform;
           }else{
               printf("Unknown model type %s\n", model_name.c_str());
               return false;
           }

           switch(m.type) {
               case ModelConstant:
                   Constant c;
                   c.value = props.second["reads"].as<unsigned int>();
                   m.c = c;
                   break;

               case ModelSequence: {
                   Sequence seq;

                   seq.offset = 0;
                   seq.values = new std::vector<int>;

                   const YAML::Node& seqvals = props.second["reads"];
                   for(unsigned i=0;i<seqvals.size();i++) {
                       int intval = seqvals[i].as<int>();
                       (*seq.values).push_back(intval);
                   }
                   m.s = seq;
                   }
                   break;

               case ModelRandomUniform: {
                   RandomUniform rnd;

                   rnd.rndseed = 0;
                   rnd.values = new std::vector<int>;

                   const YAML::Node& seqvals = props.second["reads"];
                   for(unsigned i=0;i<seqvals.size();i++) {
                       int intval = seqvals[i].as<int>();
                       (*rnd.values).push_back(intval);
                   }
                   m.r = rnd;
                   }
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
        printf("Device %s has %lu models:\n", dev.name.c_str(), dev.models.size());
        for (auto &model : dev.models) {
            printf("\tOffset %u:\n", model.offset);
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
            }

            printf("\t\tSample values:\t");
            for(int j=0;j<10;j++) 
                printf(" %u,", _generate_value(dev, model.offset));
            printf("\n");
        }
    }
}

void cleanup_devices(std::vector<Device> &devices) {
    //Cleanup
    for (auto &dev : devices) {
        printf("Device %s has %lu models:\n", dev.name.c_str(), dev.models.size());

        // Delete allocated vectors* in models where necessary
        for (auto &model : dev.models) {
            if (model.type == ModelSequence) {
                delete model.s.values;
            } else if (model.type == ModelRandomUniform) {
                delete model.r.values;
            }
        }

    }
}

bool init_plugin(void *self) {
    panda_arg_list *args = panda_get_args("holodeck");
    const char *config_path = NULL;
    if (args != NULL) {
         config_path = panda_parse_string_req(args, "config", "holodeck config file");
    }
    assert(config_path != NULL);


    
    YAML::Node config = YAML::LoadFile(config_path);

    std::vector<Device> devices;

    // Parse devices
    YAML::Node devices_y = config["devices"];

    if (!parse_devices(devices_y, devices)) {
        fprintf(stderr, "Couldn't parse input config. Aborting\n");
        assert(0);
    }

    dump_devices(devices);
    cleanup_devices(devices);

    return true;
}

void uninit_plugin(void *self) { }
