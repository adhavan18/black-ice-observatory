# authorized testing lab

the repository does not attack an external target. the safe testing scope is the local cli and its synthetic fixtures.

the testing method is:

1. run the cli against `examples/report.json` and `examples/landscape.json`;
2. verify malformed input fails without executing content;
3. run the opsec scanner against a temporary fixture containing a fake token;
4. confirm the scanner reports the fake token and never sends data over the network;
5. record the result in a review before connecting an approved internal target.

this is the correct boundary for a portfolio repository. a real penetration test requires written authorization, a named scope, rate limits, an owner, and a separate report.
