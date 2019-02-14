enum ModelType   {ModelConstant, ModelSequence, ModelRandomUniform};
enum ReadPolicy  {ReadAbort, ReadRepeat};
enum WritePolicy {WriteLast, WriteIgnore};

struct Constant {
    unsigned int value;
};

struct Sequence {
    unsigned int offset;
    std::vector<unsigned int> *values;
};

struct RandomUniform {
    int rndseed; // TODO: store random state in seed?
    std::vector<unsigned int> *values;
};


struct Model {
    ModelType type;
    unsigned int offset;

    union {
        Constant c;
        Sequence s;
        RandomUniform r;
    };

    ReadPolicy  readPolicy;
    WritePolicy writePolicy;
};

struct Device {
    std::string name;
    unsigned int start;
    unsigned int length;
    std::vector<Model> models;
};


// Given a model, return the next value
unsigned int _generate_value(Model &m);
// Given a device and an offset, return the value for the approperiate model
unsigned int _generate_value(Device &dev, unsigned int offset);
// Given an address, find a device and return value for approperiate model
unsigned int generate_value(std::vector<Device> devices, unsigned int address);

// Parse yaml object into device vector
bool parse_devices(YAML::Node &devices_y, std::vector<Device> &devices);

// Print info and sample values from devices
void dump_devices(std::vector<Device> &devices);
// Free allocated memory
void cleanup_devices(std::vector<Device> &devices);
