BIR (Binary Information Retrieval) is a tool to associate executing code with its counterpart on disk. It operates by dividing executable files into passages and precomputing n-gram statistics. The currently executing TB is then ran as a query against the database and the relevant passage is returned.

To use bir, here's what you have to do:

# Make with make -f makefile-bir all in this directory.
# Run bi.

bi says its arguments are:
usage: bi file_list_file filename_pfx min_n max_n passage_len

file_list_file: List of files to index.
filename_pfx: Prefix for output files.
min_n: minimum ngram statistic to use (use 1 if you don't know what to do)
max_n: maximum ngram statistic to use (use 3 ...)
passage_len: length of passages. Use 64 if you don't know what to do.

# Run bp.

bp says:
usage: inv_pfx max_row_length
inv_pfx is file pfx for inv index containing counts

inv_pfx: same as filename_pfx before.
max_row_length: no idea. Use 10000.

# Run panda with -panda 'bir:pfx=filename_pfx' AND SEND THE OUTPUT TO A FILE
