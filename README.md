# Zeek: Prototype Zero Knowledge Protocol Simulator

Essentially, `zeek` implements a multiparty model on top of Lurk.
One may chose to be the prover, the verifier or someone in the public.
One a party is chosen, some commands may or may not be avaiable. For
instance, a public party may not `hide` a secret but it may `verify`
proof and `check` that a given call yields a certain value in a given
proof.

This is still WIP. Proper documentation will follow. The code is quite
simple though and one may like to inspect it and play with it. Many
nice developments are foreseen, stay tuned!
    
Run it simply as `./zeek.py`.
