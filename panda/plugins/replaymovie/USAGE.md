Plugin: replaymovie
===========

Summary
-------

The `replaymovie` plugin creates a movie from a replay by taking a screenshot at regular intervals. This relies on the framebuffer still getting updated during the replay, which is not the case on all platforms. However, it works fine on x86, as long as there aren't any video mode switches in the replay.

The plugin outputs a sequence of files named `replay_movie_001.ppm`, `replay_movie_002.ppm`, etc. You can then stitch these together into a movie with `ffmpeg`. There is a script provided in the plugin directory called [movie.sh](movie.sh) that will do this for you. It creates a file named `replay.mp4`.

`replaymovie` currently takes one screenshot per one percent of the replay (in terms of instruction count). Thus, using the default 20 frames per second specified in `movie.sh`, each movie will end up being 5 seconds long. The number of screenshots taken can currently only be changed by editing the source.

Arguments
---------

None.

Dependencies
------------

`ffmpeg` or `avconv` is required to generate the movie.

APIs and Callbacks
------------------

None.

Example
-------

Generating the still frames:

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo \
        -panda replaymovie

Creating the movie:

    $PANDA_PATH/panda_plugins/movie.sh

Clean up:

    rm replay_movie_*.ppm

Watch the movie:

    ffplay replay.mp4

