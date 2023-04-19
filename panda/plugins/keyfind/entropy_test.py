import math 
import random
import statistics


def shannon_entropy(sentence): 
    entropy = 0 
    for character_i in range(256): 
        Px = sentence.count(chr(character_i))/len(sentence) 
        if Px > 0: 
            entropy += - Px * math.log(Px, 2) 
    return entropy


rounds = 100000
entropies = []
count = 0
for i in range(0, rounds):
    key ="".join([chr(random.randint(0,255)) for i in range(48)])
    e = shannon_entropy(key)
    entropies.append(e)
    if e < 5.0044:
        count += 1

mean = statistics.mean(entropies)
stdev = statistics.stdev(entropies)
print(f"(48 byte key)\nmean of entropies: {mean}, stdev: {stdev}")
print(f"threshold: {mean - (5 * stdev)}")
print(f"missed {count} potential keys out of {rounds}")

entropies = []
count = 0
for i in range(0, rounds):
    key ="".join([chr(random.randint(0,255)) for i in range(32)])# When he uses all 255 chars
    e = shannon_entropy(key)
    entropies.append(e)
    if e < 4.394:
        count += 1


mean = statistics.mean(entropies)
stdev = statistics.stdev(entropies)
print(f"(32 byte key) mean of entropies: {mean}, stdev: {stdev}")
print(f"threshold: {mean - (6 * stdev)}")
print(f"missed {count} potential keys out of {rounds}")


