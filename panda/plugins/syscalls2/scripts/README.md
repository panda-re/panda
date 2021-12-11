Syscalls2 scripts to genreate prototypes and code

Setup instructions:

```sh
python3 -m venv venv
. venv/bin/activate

pip install -r requirements2.txt
```

Then you can either:
A) Populate ../generated-in/ with the various prototypes text files using locally-cloned kernel source: `./make_all_prototypes.sh`
B) Populate ../generated/ with headers and C++ code using the prototypes text files: `./make_all_generated.sh`

Those two bash scripts are quite simple, they just call prototype_parser.py or syscalls_parser.py with the right arguments.
