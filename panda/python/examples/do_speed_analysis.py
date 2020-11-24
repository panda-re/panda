import numpy as np
def do_run_on_file(fname):
    arr = []
    num = 0
    with open(fname) as f:
        for line in f:
            if "Time taken for" in line and " before_block_exec (nanoseconds): " in line:
                arr.append(int(line.split(": ")[1]))
                num += 1
    arr = np.array(arr)
    return max(arr), min(arr), sum(arr) * 1.0 / num, np.std(arr), num

f_list = ["c_times", "py_times"]

for q in f_list:
    max_num, min_num, average, std, num_counted = do_run_on_file(q)
    print(f"{q}: average: {average} min: {min_num} max: {max_num} std: {std} sample size of {num_counted}")
