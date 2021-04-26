# Alice generates N secrets with N indices and inserts each pair [secret, index] into a puzzle that can be solved in X(N) time
# Alice sends all the puzzles to Bob
# ---------------------------------->
# Bob randomly picks one puzzle and gets a pair [secret, index] by solving the puzzle
# Bob sends the index back to Alice
# <----------------------------------
# based on the index, they both share a common secret, now
# adversary knows all Alice’s puzzles and Bob’s index; to find the secret she has to solve N puzzles to compare indices which requires X(N^2) time

# Example, to enforce X(2^32) Alice needs to generate X(2^16) total amount of puzzles

from os import urandom
from hashlib import sha1
from random import shuffle, choice

# Merkles-Puzzles

puzzle_size = 2 ** 16

def merkles_puzzle():
    sec = [None] * puzzle_size
    puzzles = [None] * puzzle_size

    for i in range(puzzle_size):
        # secret generation
        sec[i] = urandom(16)

        # secret + index as a pair
        pair = sec[i] + int.to_bytes(i, 4, 'big')
        # pair and sha1
        plaintxt = pair + sha1(pair).digest()

        # encryption process:
        key = urandom(10)
        noise = sha1(key).digest()
        noise += sha1(noise).digest()
        ciphertxt = bytes(i ^ j for i, j in zip(plaintxt, noise))

        # puzzle:
        puzzles[i] = ciphertxt + key[2:]

    # random
    shuffle(puzzles)

    # return
    return sec, puzzles

def solve_puzzle(puzzle):
    ciphertxt = puzzle[:40]
    key = puzzle[40:]

    for i in range(puzzle_size):
        # guess possibilities
        noise = sha1(int.to_bytes(i, 2, 'big') + key).digest()
        noise += sha1(noise).digest()

        # decryption process
        plaintxt = bytes(i ^ j for i, j in zip(ciphertxt, noise))

        # pair
        pair = plaintxt[:20]
        digest = plaintxt[20:]

        # time, key and index
        if sha1(pair).digest() == digest:
            return i, pair[:16], int.from_bytes(pair[16:], 'big')

alice_sec, public_puzzles = merkles_puzzle()

bob_time, bob_secret, public_index = solve_puzzle(choice(public_puzzles))

print('Secret and index published by BOB')
print('Full key:', bob_secret)
print('Public Index:', public_index)
print('Total steps executed:', bob_time)

print('Secret shared by ALICE ')
print('Full key:', alice_sec[public_index])

total_time, total_puzzles = 0, 0

for puzzle in public_puzzles:
    adv_time, adv_key, adv_index = solve_puzzle(puzzle)
    total_time += adv_time
    total_puzzles += 1

    if adv_index == public_index:
        print('Shit! The secret has been found!:', adv_key)
        break

    if total_time > bob_time * 100:
        print('Not this time! You pesky attacker!')
        break

print('searched puzzles:', total_puzzles, 'steps executed:', total_time)

# END