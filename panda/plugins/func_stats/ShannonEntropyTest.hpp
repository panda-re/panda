#pragma once

#include <stdint.h>
#include <string.h>
#include <math.h>

/** A class to compute byte entropy of 256 bytes buffer**/
class ShannonEntropyTest {
    uint32_t bytecount[256] = {0};
    uint32_t length = 0;

public:
    void add(uint8_t byte){
        bytecount[byte]++;
        length++;
    }
    float get(){
        float entropy = 0;
        for (int i = 0; i < 256; i++){
            if (bytecount[i]){
                float frequency = static_cast<float>(bytecount[i]) / static_cast<float>(length);
                entropy += -frequency * log2f(frequency);
             }
        }
        return entropy;
    }
    void reset(){
        memset(bytecount, 0, sizeof(bytecount));
        length = 0;
    }
};
