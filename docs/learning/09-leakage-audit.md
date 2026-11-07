# Milestone 5b: proving that a server learns nothing

## What "learns nothing" means

A server in darkmpc sees a great deal. It holds shares of every order, it receives millions of numbers from the other two servers during an auction, and every so often the servers open a value and all three see it in the clear. The claim that it learns nothing about the orders cannot mean that it sees nothing. It has to mean that everything it sees is useless for telling one batch of orders from another.

Cryptographers make this precise with a *simulator*. Imagine a program that is told only the public facts, the batch size and the configuration, and never sees an order. If that program can produce a fake transcript that looks exactly like what the real server would see, then the real transcript cannot contain information about the orders. Anything the server could compute from its real view, it could have computed from the fake one, which was made without the orders. The whole proof is a recipe for that program, plus an argument that its output is indistinguishable from reality.

## Why the recipe is short

The recipe is short because the protocol is built from only four kinds of interaction, and each has a simple reason to be harmless.

The first is the server's own shares of the inputs. A trader splits each number into three random-looking pieces that add up to it, and each server holds two. Any two of the three pieces are just two uniformly random numbers, whatever the order was, so the simulator draws two random numbers.

The second is the message that arrives during a multiplication. It carries a mask built from a pseudorandom stream that the receiving server has no key for. Without the key, that mask is as good as fresh random noise, and noise added to anything is uniform noise. The simulator sends random words. This is the step that leans on cryptography: if AES could be told apart from randomness, the argument would break, and the proof's first move, the *hybrid* step, replaces that one stream with true randomness and pays exactly the PRF's distinguishing advantage for it.

The third is the shuffle. Each of its three steps is run by a pair of servers and hides its piece of the permutation from the third. When the hidden piece is this server's own blind spot, the two numbers it receives are masked by fresh randomness from that same keyless stream, so they are uniform too. In the other two steps it only sends.

The fourth, and the only place a server sees a value in the clear, is the opening of a shuffled permutation. The servers need to apply a secret sorting permutation $\rho$, so they first compose it with the random shuffle $\pi$ and only then open it. Our server knows two of the three pieces of $\pi$ but not the third, and composing anything with a uniformly random permutation it does not know gives a uniformly random permutation. So the opened value is a random permutation, whatever the data was, and the simulator draws one. The server then applies that public permutation to its shares. It has learned a random shuffle of the data's order, which is to say nothing.

Put the four together in the order the protocol runs them, and the simulator has a rule for every message. Because each rule produces the right distribution *given everything before it*, the whole fake transcript has the right distribution. That chaining step is what turns four local facts into a theorem about an entire auction.

## What the tests add

A proof is about the protocol as written on paper. The tests ask whether the code is that protocol. The proof needs two facts about the code, and each has a test.

The first fact is that the *shape* of the traffic, how many messages and how long, depends only on the public facts. If the code ever branched on a secret, say by skipping work for an empty book, the message pattern itself would leak. The shape test runs two very different batches and requires every server's traffic to match exactly, message for message.

The second fact is that every opening is either a random permutation or a fixed constant. The opening test runs each batch hundreds of times and checks, opening by opening, that the distribution of what was opened does not depend on the batch.

A test is only worth something if it can fail, so two leaks are planted. One forgets to shuffle before opening, which publishes the order of the data. The other leaves behind a stray "print the clearing price" opening, a mistake real developers make while debugging. Neither changes a single fill or price, so every correctness test in the project passes with them switched on. The audit catches both, at the strongest signal the statistic can give. That is the point of the exercise: a class of bug that no amount of output checking can see, caught by checking the view instead.

## The honest limits

The proof covers servers that follow the protocol. A server that actively cheats could try to make an opening depend on a secret, for example by tampering with a shuffle and watching whether the result is still a valid permutation. Milestone 4 built the defences against that. Proving that they work, with simulation against a cheating server and the two ring extensions argued in full, is the main proof of the final write-up. Timing and memory side channels are outside the proof altogether. And nothing here hides what the auction itself must reveal to traders, which the threat model lists plainly.
