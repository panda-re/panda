Plugin: replaymovie
===========

Summary
-------

The `replaymovie` plugin creates a movie from a replay by taking a screenshot at regular intervals. This relies on the framebuffer still getting updated during the replay, which is not the case on all platforms. However, it works fine on x86, as long as there aren't any video mode switches in the replay.

The plugin outputs a sequence of files named `replay_movie_000.ppm`, `replay_movie_001.ppm`, etc. You can then stitch these together into a movie with `ffmpeg`. There is a script provided in the plugin directory called [movie.sh](movie.sh) that will do this for you. It creates a file named `replay.mp4`.

If you use the `save_instruction_count` option, then the `replaymovie` plugin will also create a file named `replay_movie_counters.txt`.  This file is used by the [moviecounter.sh](moviecounter.sh) script to put the instruction counter for each frame at the desired location on each image before they are stitched together.  (This script will tweak the counter placement calculated from `xfraction` and `yfraction` to ensure that the label is not off screen.)  The individual labeled images are named `replay_movie_counter000.ppm`, `replay_movie_counter001.ppm`, etc.  The movie file is named `moviecounter.mp4`.

`replaymovie` currently takes one screenshot per one percent of the replay (in terms of instruction count). Thus, using the default 20 frames per second specified in `movie.sh` or `moviecounter.sh`, each movie will end up being 5 seconds long. The number of screenshots taken can currently only be changed by editing the source.

Arguments
---------

* `save_instruction_count` - When `true`, also saves instruction count placement and counter information (default:  `false`)
* `xfraction` - Fraction along the X axis at which to place the instruction count (default:  1.0; 0.0 is left edge, 1.0 is right edge)
* `yfraction` - Fraction along the Y axis at which to place the instruction count (default:  1.0; 0.0 is top edge, 1.0 is bottom edge)

Dependencies
------------

`ffmpeg` or `avconv` is required to generate the movie.
If `moviecounter.sh` is used, then `netpbm` is also required to label the images.

APIs and Callbacks
------------------

None.

Example
-------

Generating the still frames:

    $PANDA_PATH/x86_64-softmmu/panda-system-x86_64 -replay foo \
        -panda replaymovie

Creating the movie:

    $PLUGINS_PATH/replaymovie/movie.sh

Clean up:

    rm replay_movie_*.ppm

Watch the movie:

    ffplay replay.mp4

