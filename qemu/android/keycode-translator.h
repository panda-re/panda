#if !defined(ANDROID_KEYCODE_TRANSLATOR_H)
#define ANDROID_KEYCODE_TRANSLATOR_H
//struct AndroidKeycodeState {
//    bool hasBit7;
//};

//typedef struct AndroidKeycodeState AndroidKeycodeState_t;

// console.h says keycode is an int
//C++ would make this more pleasant
int translateToAndroid(bool* hasBit7, int keycode);

#endif
