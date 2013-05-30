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

#ifndef ANDROID_CAMERA_CAMERA_WIN_H_
#define ANDROID_CAMERA_CAMERA_WIN_H_

/*
 * Contains declarations that are missing in non-Linux headers.
 */

/*  Four-character-code (FOURCC) */
#define v4l2_fourcc(a,b,c,d)\
    (((uint32_t)(a)<<0)|((uint32_t)(b)<<8)|((uint32_t)(c)<<16)|((uint32_t)(d)<<24))

/*      Pixel format         FOURCC                        depth  Description  */
#define V4L2_PIX_FMT_RGB332  v4l2_fourcc('R','G','B','1') /*  8  RGB-3-3-2     */
#define V4L2_PIX_FMT_RGB444  v4l2_fourcc('R','4','4','4') /* 16  xxxxrrrr ggggbbbb */
#define V4L2_PIX_FMT_RGB555  v4l2_fourcc('R','G','B','O') /* 16  RGB-5-5-5     */
#define V4L2_PIX_FMT_RGB565  v4l2_fourcc('R','G','B','P') /* 16  RGB-5-6-5     */
#define V4L2_PIX_FMT_RGB555X v4l2_fourcc('R','G','B','Q') /* 16  RGB-5-5-5 BE  */
#define V4L2_PIX_FMT_RGB565X v4l2_fourcc('R','G','B','R') /* 16  RGB-5-6-5 BE  */
#define V4L2_PIX_FMT_BGR24   v4l2_fourcc('B','G','R','3') /* 24  BGR-8-8-8     */
#define V4L2_PIX_FMT_RGB24   v4l2_fourcc('R','G','B','3') /* 24  RGB-8-8-8     */
#define V4L2_PIX_FMT_BGR32   v4l2_fourcc('B','G','R','4') /* 32  BGR-8-8-8-8   */
#define V4L2_PIX_FMT_RGB32   v4l2_fourcc('R','G','B','4') /* 32  RGB-8-8-8-8   */
#define V4L2_PIX_FMT_GREY    v4l2_fourcc('G','R','E','Y') /*  8  Greyscale     */
#define V4L2_PIX_FMT_PAL8    v4l2_fourcc('P','A','L','8') /*  8  8-bit palette */
#define V4L2_PIX_FMT_YVU410  v4l2_fourcc('Y','V','U','9') /*  9  YVU 4:1:0     */
#define V4L2_PIX_FMT_YVU420  v4l2_fourcc('Y','V','1','2') /* 12  YVU 4:2:0     */
#define V4L2_PIX_FMT_YUYV    v4l2_fourcc('Y','U','Y','V') /* 16  YUV 4:2:2     */
#define V4L2_PIX_FMT_UYVY    v4l2_fourcc('U','Y','V','Y') /* 16  YUV 4:2:2     */
#define V4L2_PIX_FMT_YUV422P v4l2_fourcc('4','2','2','P') /* 16  YVU422 planar */
#define V4L2_PIX_FMT_YUV411P v4l2_fourcc('4','1','1','P') /* 16  YVU411 planar */
#define V4L2_PIX_FMT_Y41P    v4l2_fourcc('Y','4','1','P') /* 12  YUV 4:1:1     */
#define V4L2_PIX_FMT_YUV444  v4l2_fourcc('Y','4','4','4') /* 16  xxxxyyyy uuuuvvvv */
#define V4L2_PIX_FMT_YUV555  v4l2_fourcc('Y','U','V','O') /* 16  YUV-5-5-5     */
#define V4L2_PIX_FMT_YUV565  v4l2_fourcc('Y','U','V','P') /* 16  YUV-5-6-5     */
#define V4L2_PIX_FMT_YUV32   v4l2_fourcc('Y','U','V','4') /* 32  YUV-8-8-8-8   */

/* two planes -- one Y, one Cr + Cb interleaved  */
#define V4L2_PIX_FMT_NV12    v4l2_fourcc('N','V','1','2') /* 12  Y/CbCr 4:2:0  */
#define V4L2_PIX_FMT_NV21    v4l2_fourcc('N','V','2','1') /* 12  Y/CrCb 4:2:0  */

/*  The following formats are not defined in the V4L2 specification */
#define V4L2_PIX_FMT_YUV410  v4l2_fourcc('Y','U','V','9') /*  9  YUV 4:1:0     */
#define V4L2_PIX_FMT_YUV420  v4l2_fourcc('Y','U','1','2') /* 12  YUV 4:2:0     */
#define V4L2_PIX_FMT_YYUV    v4l2_fourcc('Y','Y','U','V') /* 16  YUV 4:2:2     */
#define V4L2_PIX_FMT_HI240   v4l2_fourcc('H','I','2','4') /*  8  8-bit color   */
#define V4L2_PIX_FMT_HM12    v4l2_fourcc('H','M','1','2') /*  8  YUV 4:2:0 16x16 macroblocks */

/* Bayer formats - see http://www.siliconimaging.com/RGB%20Bayer.htm */
#define V4L2_PIX_FMT_SBGGR8  v4l2_fourcc('B', 'A', '8', '1') /*  8  BGBG.. GRGR.. */
#define V4L2_PIX_FMT_SGBRG8  v4l2_fourcc('G', 'B', 'R', 'G') /*  8  GBGB.. RGRG.. */
#define V4L2_PIX_FMT_SGRBG8  v4l2_fourcc('G', 'R', 'B', 'G') /*  8  GRGR.. BGBG.. */
#define V4L2_PIX_FMT_SRGGB8  v4l2_fourcc('R', 'G', 'G', 'B') /*  8  RGRG.. GBGB.. */
#define V4L2_PIX_FMT_SBGGR10 v4l2_fourcc('B', 'G', '1', '\0') /* 10  BGBG.. GRGR.. */
#define V4L2_PIX_FMT_SGBRG10 v4l2_fourcc('G', 'B', '1', '\0') /* 10  GBGB.. RGRG.. */
#define V4L2_PIX_FMT_SGRBG10 v4l2_fourcc('B', 'A', '1', '\0') /* 10  GRGR.. BGBG.. */
#define V4L2_PIX_FMT_SRGGB10 v4l2_fourcc('R', 'G', '1', '\0') /* 10  RGRG.. GBGB.. */
#define V4L2_PIX_FMT_SBGGR12 v4l2_fourcc('B', 'G', '1', '2') /* 12  BGBG.. GRGR.. */
#define V4L2_PIX_FMT_SGBRG12 v4l2_fourcc('G', 'B', '1', '2') /* 12  GBGB.. RGRG.. */
#define V4L2_PIX_FMT_SGRBG12 v4l2_fourcc('B', 'A', '1', '2') /* 12  GRGR.. BGBG.. */
#define V4L2_PIX_FMT_SRGGB12 v4l2_fourcc('R', 'G', '1', '2') /* 12  RGRG.. GBGB.. */

#endif  /* ANDROID_CAMERA_CAMERA_WIN_H_ */
