/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ANDROID_CAMERA_CAMERA_SERVICE_H_
#define ANDROID_CAMERA_CAMERA_SERVICE_H_

/*
 * Contains public camera service API.
 */

/* Initializes camera emulation service over qemu pipe. */
extern void android_camera_service_init(void);

/* Lists available web cameras. */
extern void android_list_web_cameras(void);

#endif  /* ANDROID_CAMERA_CAMERA_SERVICE_H_ */
