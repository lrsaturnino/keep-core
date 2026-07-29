# Release rehearsal and smoke harnesses

This directory holds the release-engineering scaffolding for the coordinated
security release:

1. the container smoke matrix for the temporary `clientInfo.port` **9601
   compatibility default** — `clientinfo-port-smoke.sh` and `compose.yaml`;
2. the single-release **cutover rehearsal** scaffold — `rehearse.sh`,
   `compose.rehearsal.yaml`, and `rehearsal-evidence.schema.json`, driven
   manually or through the `cutover-rehearsal` workflow; and
3. the **release manifest** binding the service-manager termination grace to
   the client's compiled protocol bounds — `release-manifest.json`,
   `release-manifest.schema.json`, and the deployment scaffold under
   `deploy/`.

## Cutover rehearsal scaffold

The chain-clocked cutover machinery — the participation gate, per-ceremony
permits, commit fences, quiescence and the signal lifecycle controller, and
the signer quarantine namespace — is implemented in this tree and proven by
repository-local Go tests, together with the tBTC cutover ceremony
acceptance suites under the race detector: real security-v2 key-generation
transcripts — including the ten-misbehaved-seat real result — the
production-scale 90/10 split exclusion, heartbeat inactivity bands, and
cutover roster wiring, ending with an explicit report of every skipped case.
Run those proofs, which need no Docker or chain, with:

```
./rehearse.sh local-proofs
```

Three sibling stages cover the rest of the changed risk surface locally:
`./rehearse.sh static-analysis` runs the CI-enforced Go analyzers with
every tool at an immutable version — gofmt, `go vet ./...` (strictly wider
than CI's root-only vet), staticcheck 2025.1.1, gosec v2.28.0 (CI's own
gosec action floats on `master`; the pin keeps the evidence reproducible),
and golangci-lint v2.12.2 — `./rehearse.sh solidity-proofs` builds and
tests the ECDSA contracts exactly as the contracts workflow's
`contracts-build-and-test` job does: the exact Node release that job pins,
read out of it rather than restated here, plus the Corepack-managed yarn
from `packageManager` and a never-skipped `yarn install --immutable` before
`yarn build` and `yarn test` — and `./rehearse.sh shell-analysis` analyzes this scaffold
itself: `bash -n` and ShellCheck over every script here, actionlint v1.7.12
over the scaffold's own workflows (scoped to them on purpose; the unrelated
workflows carry pre-existing findings, and a gate that is red for reasons
outside its scope stops being read), and both validator self-tests. That
last stage is the one CI runs unconditionally — see
`.github/workflows/cutover-scaffold-lint.yml` below — because the checkers
that admit rehearsal evidence must never be proved only by a manual
dispatch. Every stage stamps the exact source commit into its log,
marking any divergence from `HEAD` — untracked files included — as
`-dirty`. Setting `PR4109_EXPECTED_SOURCE_COMMIT` makes the stamp a
fail-closed binding instead: the stage refuses to run at all unless the
tree under test is exactly that commit, so a log carrying a verified stamp
is proof the stamped bytes were the tested bytes.

The offline state classification the rollback barrier requires runs with
`go run ./cmd/participation-state-audit --storage-snapshot <copy>`: it
records the snapshot identity (aggregate checksum and access mode), flags any
entry outside the expected storage layout, and — when the storage password is
supplied — interprets the beacon active, beacon quarantine, and tBTC active
namespaces with the same decode paths the client's own loaders use,
cross-validating quarantine metadata against its schema, epoch, mode/anchor
arithmetic, storage location, and decrypted membership. Namespace consistency
alone is never rollback-ready: the audit exits nonzero until references to
the chain reconciliation, Bitcoin reconciliation, quiescence outcome, and
prior-reader compatibility evidence are supplied via its
`--*-evidence`/`--quiescence-report` flags **and** the expected operational
identities the evidence must bind to are supplied via its `--expected-*`
flags — Ethereum chain ID, Bitcoin network, the exact prior and current
release versions, revisions, and immutable image digests, the release epoch,
the armed cutover block, and the evidence freshness bound. Chain evidence has
additional independent inputs: the exact WalletRegistry and RandomBeacon
addresses, a finalized Ethereum block number/hash obtained outside the evidence
generator, and the lowercase hexadecimal Ed25519 public key of the trusted chain
collector. Its output never authorizes activating quarantined material by
itself.
For every reconciled tBTC wallet whose DKG settlement is not `none`, schema
v8 requires the complete `DkgStarted`, `DkgResultSubmitted`,
`DkgResultApproved`, and `WalletCreated` event lineage. Each event names its
transaction hash, block hash/number, and log index; the submitted event carries
the full on-chain result tuple, not caller-supplied summary fields. The same
record carries the successful receipt projections and exact address,
topics/data, and log indexes. The audit verifies the collector signature over
the entire record, requires each receipt block in the signed canonical set,
binds that set to the independently supplied finalized block, rejects logs
from any address other than the independently supplied WalletRegistry, and
re-derives every decoded event field from the raw log bytes. A self-consistent
history produced by an untrusted generator, a failed receipt, an unrelated
contract, or a non-canonical block therefore blocks rollback. The audit also
recomputes `keccak256(abi.encode(result))`, the operating-members hash, the
seed hash, and the wallet ID, requires approval and wallet creation to share
one receipt, and derives the original and final group shapes from those bytes.
Its `signing_member_indexes` decode at the contract's full `uint256` width
before the protocol's one-byte group bounds are enforced. For an approved
wallet it then maps each original DKG permit to the persisted final membership;
a forged result hash, unrelated approved wallet, or two persisted memberships
swapped between permits blocks rollback.

The same record settles the penalties a node recorded as its permits' results.
A heartbeat's inactivity claim must be corroborated by a canonical
`InactivityClaimed` log for the exact wallet and nonce named, emitted by the
supplied WalletRegistry, and the punished wallet must be the one the permit is
about. A relay entry timeout report must be corroborated by a canonical
`RelayEntryTimedOut` log naming the exact request identifier and terminated
group, emitted by the supplied RandomBeacon, whose `RelayEntryRequested` log
sits in the very block the reporting permit was issued for and which no
`RelayEntrySubmitted` log answers. Filing a report is not earning a penalty — a
transaction that reverts, is dropped, or loses the race to another reporter
leaves the beacon exactly as it was and renders exactly the same node-authored
reference — so a settlement the beacon's own logs do not carry blocks rollback.

The rollback rehearsal runs that audit **twice over the same snapshot**, and
the order is the whole point. Every external record must carry the audited
snapshot's `snapshot_aggregate_sha256`, and the audit rejects any that names
another — so that checksum is a fact about state this rehearsal has only just
produced by draining the fleet and copying it out. Evidence handed in before
the fleet drained could not have known it, and evidence that named it anyway
would be describing a drain that had not happened. So the first pass runs with
no evidence at all and exists to derive the snapshot identity and interpreted
inventory; the supplied `PR4109_ROLLBACK_EVIDENCE_GENERATOR` is then executed
as `<service> <identity-manifest> <output-directory>` and must write
`chain-reconciliation.json`, `bitcoin-reconciliation.json`,
`quiescence-report.json`, and `prior-reader-compatibility.json` for that
snapshot; and the second pass, over those records, is the one that authorizes
anything. A generator that failed, that wrote only some of the four, or that
cannot be run leaves the barrier unestablished rather than the audit refusing.
The node writes an encrypted
`work/participation/quiescence/gate-snapshot.json` artifact while the gate
holds the same lock that changes its state to `quiescing`. That node-authored
artifact binds the exact active-permit registry and total, legacy, and
security-v2 counts to the running version, revision, compiled epoch, C,
current block, cause, and transition instant. It is part of the stopped
storage snapshot and therefore of `snapshot_aggregate_sha256`; the external
evidence generator cannot replace it with a second self-attested inventory.
Each process run invalidates the prior artifact before constructing its gate,
so a restart or failed new capture leaves the rollback audit fail-closed
instead of exposing stale inventory.
The schema-v8 quiescence record supplies only the later
`active_permits_at_quiescence` terminal-outcome list, which must cover the
node-authored inventory one-to-one and reproduce all three counts. An empty or
shortened outcome list over a nonempty gate artifact blocks rollback. Both
records name `work_id` and `permit_id` as well as ceremony, mode, and anchor.
DKG claims use the canonical SHA-256 seed hash (exactly 64 lowercase
hexadecimal characters) and the canonical decimal member index (1 through
255) respectively. Beacon relay-signing permits likewise use the member
index; other work and permit identities use the driver's stable identifier
alphabet. The audit rejects an unbound or repeated full permit identity, a
zero canonical anchor under an armed schedule, and any identity contradicting
the cutover arithmetic (`legacy` below C, `security_v2` at or above C),
including completed outcomes. Quarantined claims additionally match the exact
local permit rather than letting one output cover another event or membership
at the same block.

The identities the audit binds that evidence to — the release being rolled
back: version, revision, epoch, and armed C — come from what the R1 fleet
itself reported while it was still up, so the rollback is authorized against
what ran rather than against what anyone believed ran. The stage then reads
`rollback_barrier_ready` out of the manifest the authorizing pass wrote. Both
manifests and the generated records are kept under `state-audit/` in the
evidence directory whether the audit authorized the rollback or refused it —
a refusal is the part of a rollback decision most worth reading — and one
level down rather than beside the rehearsal record, because the acceptance
stage validates every top-level JSON against the rehearsal record schema and
an audit manifest is a different document.

The two **container** rehearsals are mandatory release gates that cannot run
from this repository alone: they need the immutable prior-production and R1
runtime image digests, an equally immutable probe image digest, a rehearsal
chain with deployed beacon/tBTC contracts and its chain id, per-node operator
keys and configs each declaring a nonzero `clientInfo.port`, a work driver
that originates protocol work on that chain, and (for rollback) a directory
to capture each drained node's state into. `rehearse.sh preflight` validates
those inputs and reports `BLOCKED` with the exact missing one. The rollback
gate additionally needs the audit inputs no storage snapshot can supply — the
rollback evidence generator that produces the chain and Bitcoin
reconciliation, quiescence outcome, and prior-reader compatibility records for
each captured snapshot, the independently provisioned WalletRegistry/finalized
block/collector-key trust inputs, plus the Bitcoin network and the prior
artifact's version and revision — because without them the audit can classify
namespaces and authorize nothing.

Once preflight passes, `single-release` and `rollback` **run**: each drives
its gate as an explicit sequence of steps, starting the fleet from the
immutable digests, reading every number it records from the nodes' own
client-info ports over the internal rehearsal network, and recording each
step's own outcome. Which services a gate starts is part of what it proves:
the cutover rehearsal needs the prior binary on the network from the start,
because it *is* the straggler the negative control is about, while the
rollback rehearsal starts only the R1 fleet — its whole subject is that no
prior binary participates until the barrier holds, and a fleet that brought
the prior service up with everything else would have put the thing under test
on the network before the first step ran. It does *stage* the prior
container: created from the audited digest, proved not running, and left off
the network, because `compose start` can only start something that exists and
a rollback project that created nothing would leave the release step
recording a rollback it never performed.

Before either gate touches the fleet it proves the containers are running the
supplied digests — image IDs compared against what the daemon actually created
each container from, because a stale local tag or an edited compose file
otherwise produces a fleet running other bytes under a record naming these
ones — and then captures what that fleet says it is: version, revision,
compiled protocol epoch, and armed cutover block, from *every* R1 node and not
the first. Any disagreement between nodes refuses the run, as does a revision
that is not exactly the commit the run is bound to — an abbreviation names a
commit only as far as it goes, which is why the release workflow stamps the
whole SHA and `shell-analysis` holds it to that — an armed cutover block that is not
the rehearsed C, or a protocol epoch that is not the one the reviewed manifest
was derived for. The record is
then built from what was captured rather than from what the driver was told,
so its epoch and C are the fleet's own and not a restatement of the
environment. Capturing up front is also what lets the rollback gate emit a
record at all: by the time it concludes it has stopped every R1 node on
purpose, and a reading taken then would be no reading. A step this release cannot execute is recorded `blocked`
with the reason rather than aborting the run, because the steps after it are
independent proofs and losing them tells a reviewer less than a record naming
exactly which step could not run. A step that *did* run and observed the
property violated is recorded `fail` the same way, and an acceptance
assertion is written `true` only where the run watched the property hold, so
an unobserved one reads as refused rather than as satisfied.

Every run therefore ends with an evidence record on disk — shape-checked by
the acceptance stage's own validator — and the stage's exit is decided from
the recorded outcomes. A failed step is the strongest verdict and exits
`FAIL`: the rehearsal reached the property, watched it, and watched it break,
which outranks anything the run could not reach. A step that never executed
exits `BLOCKED`: the gate is unproved rather than disproved. A refused
acceptance assertion with no step behind it exits `FAIL` too. Only a run with
none of the three reports success. A partial rehearsal can never read as a
passed gate, a failed one can never read as either, and a refused gate is
never silent about what it did prove.

Each step is held to the property it names rather than to a proxy for it. The
crossing step establishes the pre-C side first — every node reporting
`open_legacy` at a block below the C it armed — because a fleet started after
C already reports `open_security_v2` and would satisfy every closing check
without having crossed anything; it names a permit mode in the record only
where security-v2 permits were actually observed. The homogeneous positive
control requires the fleet's security-v2 permit total to *rise* while the
work driver runs, since a zero legacy counter is equally true of a fleet that
ran nothing — and it compares the legacy counter as a delta across the step,
because that counter is cumulative and the pre-C legacy controls this same
gate requires would otherwise fail this step on permits taken before C. It
also requires the driver to have reported the transactions it submitted, so a
counter that moved for some unrelated reason is not credited to ceremonies
nobody can show were originated.

The in-flight half of the crossing names the permits rather than counting
them. The gate publishes its live permits at `/diagnostics`
(`protocol_participation.active_permits`), so the control reads the fleet's own
list of what it holds before C, again at the instant every gate reports
`open_security_v2`, and requires both to be exactly the permits the driver said
it put there — no named permit the gates never held, and no unnamed permit
crossing beside them. A count that moves in step is satisfied by any two
unrelated ceremonies, and a permit gone by the crossing now fails the step
rather than being read off a completion counter that happened to move
afterwards. Only identity-bound permits count: an unbound permit names no chain
work, so matching one would be reading the count again under another name.

One permit legitimately arrives between the two readings — the quiescence
control's seed, put on the chain after this work was originated and before the
crossing — and it is excused by identity, not by node. What is excused is the
intersection of the two independent readings of that seeding: the identities
the driver said it originated on the seed node, and the identities that node's
own gate reported holding below C. The gate's reading alone is that node's
whole legacy population, so excusing it wholesale would wave through any permit
that merely turned up there between the samples; the driver's alone is the
driver's word for a below-C anchor, which is what the seeding is checked for. A
gate that could not be read below C agrees with nothing and excuses nothing.

The straggler control reads the announcer's own account of the sighting
rather than the gate's refusal counter, which counts a node declining its own
`Begin` for reasons that need no legacy announcement behind them. It requires
the whole chain: a session-ID mismatch arrived, this node recognized it as
cross-format, that recognition became a legacy roster addition, and the
roster names an operator it had not already seen. A mismatch nothing
recognized as cross-format fails the step rather than leaving a gap — the
release's premise is that a straggler is identified — and the roster object
exists from startup with an empty peer list, so its presence proves nothing.

The clock-failure step reads its contract as two halves and needs evidence
for both. With the endpoint severed the gate must report `clock_unavailable`;
it must have canceled every ceremony it was holding, counted from the
clock-abort counter rather than from the active gauge, because permits stay
counted until their owners close them and a falling gauge is the owners
noticing rather than the gate acting; and it must refuse work *offered to it
while it is blind*, which the step originates and then requires a refusal to
be recorded against. A node nobody asked produces exactly the same unchanged
permit counter as one that refused. A node that was idle when its clock
failed exercises only the refusal half and records the step blocked rather
than passing.

Quiescence requires a security-v2 ceremony to be in flight when the stop is
issued, stops the node under the reviewed manifest's grace rather than a
restated number, and watches the whole drain. It offers new work once the
node reports `quiescing` and decides issuance from the permit counter rather
than from a peak of the active gauge, which a permit taken and closed between
two samples never raises. It requires the in-flight count to have been *seen*
at zero, because a node that stopped answering while still holding permits is
indistinguishable in its last reading from one that finished them, and it
blocks rather than passes on a counter it could not read.

The refusal it records has to belong to the work it offered. The offer retains
the ceremonies the driver put on the chain, and one of *those* per-ceremony
refusal counters must be the one that moved. A per-ceremony delta on its own
only says the node refused something: a rehearsal chain carries other traffic,
and any unrelated ceremony refused for its own reasons moves the total and one
per-ceremony counter together, which is precisely the reading this step looks
for. An offer that named no ceremony it originated blocks, because nothing can
then be tied back to it.

The work driver reports what it originated rather than only whether it
succeeded: its stdout is a JSON object whose optional `transaction_hashes`
array carries the chain transactions it submitted — those enter the step being
recorded, so a reviewer can follow a step back to the transactions that caused
it — and whose optional `ceremony_results` array carries `{ceremony,
canonical_start_block, work_id, outcome, transaction_hash}` objects naming the
terminal result of each ceremony those transactions started. The results are there
because no fleet counter carries them: a permit says a node was allowed to
begin, and the positive control is about a ceremony finishing. An optional
`originated_ceremonies` array carries `{ceremony, canonical_start_block,
work_id, transaction_hash, holders}` objects naming what the driver put on the
chain whatever became of it, for the phases whose subject is work still in
flight — a drain, a forced deadline — which have no terminal outcome to read,
since by the time one exists the work it was about is over. `holders` is an
array of `{service, permit_id}` records, one for every local permit rather than
a set of node names. Every array is validated strictly, and a report that
cannot be read stops the step — a driver whose account is unreadable has left
the step unable to say what it drove, and recording that as "nothing happened"
would enter silence as evidence.

Every successful result additionally carries a `contributors` array of
`{service, permit_id}` records naming each party whose share the settled
transcript incorporated, no party twice. The mixed prior/R1 controls read it
and nothing else can answer the question they ask: that the prior binary's
container was running says only that it was running. Unselected, partitioned,
and cryptographically excluded all leave it up beside a ceremony that settled
without it, which from outside is the same reading interoperation produces. The
pre-cutover steps therefore require, in *each* required family, one settled
transcript whose contributors include both the prior service and one of the
rehearsed R1 services. Each half of that is load-bearing. Per family, because a
prior binary in a tBTC signing says nothing about the beacon's separate path
into the gate. Both services, because a release that settles a ceremony among
its own kind is homogeneous whichever release it is, and a control that only
looked for the prior share would read a prior-only ceremony as interoperation.
Within one transcript, because a prior-only wallet action beside an R1-only
signing is two homogeneous ceremonies, and what the control claims is that the
two wire formats combined into a single threshold output — which only a
transcript naming both parties ever witnesses. A service that is neither the
prior binary nor a rehearsed R1 node satisfies neither side, so a stray
container cannot stand in for either release. A driver that cannot report who
contributed cannot support a mixed-fleet claim, so the field is mandatory on
success rather than optional.

Each outcome is bound to the work it belongs to, and controls are decided on
the bound form rather than on the arrays beside it. One chain work item is
`<ceremony>@<block>@<work_id>`: the canonical start block pins the mode, while
`work_id` is the chain-native request, group, wallet/action, or DKG-seed
identity that distinguishes several events in one block. One local permit is
that work identity plus `<service>~<permit_id>`. The permit ID is the local
membership/member index or stable wallet/action identity, so one node
controlling two members at the same anchor retains two permit records. A piece
of chain work is originated once and ends once, while each local permit is
also unique. A repeated identity, one transaction claimed by two pieces of
work, or one work item changing transactions stops the step rather than being
counted twice or rebound downstream. A later terminal phase must retain the
exact transaction recorded by the originating phase.

Everything above is the report checked against itself, and a report that is
internally consistent and entirely invented passes all of it. So the chain is
asked. Every transaction a report names must have a receipt on the endpoint
supplied as `ETH_RPC_URL`, that receipt must say the transaction succeeded, and
each piece of work must be anchored at or after the block its own transaction
landed in — an anchor before it is a permit pinning its mode from a block at
which the work did not exist, which is precisely what invented anchors look
like. A reverted transaction is the same shape as a successful one from
outside, and an unmined one is the same shape as work in flight, so both stop
the step rather than being read as the work a control was decided on. The
endpoint is itself checked against the rehearsed chain id, asked of the
endpoint rather than restated from the dispatch input: one answering about
another chain confirms transactions that have nothing to do with this
rehearsal, in exactly the same shape.

A result must name a `transaction_hash` the same report accounted for
originating; without that, the hashes and the outcomes are two independent
populations, and a stale or unrelated hash sitting beside an unrelated result
satisfies any control that reads them in parallel. A result that succeeded must
carry a `result` identity — the threshold output the ceremony left behind —
because "succeeded" is a word and a positive control that cannot name what was
produced has read a report rather than watched a ceremony settle. A result that
did not succeed must carry a `termination` of `retry_exhausted` or
`no_threshold`, because a bare "failed" is equally what a ceremony still
retrying looks like from outside, and a fails-closed control cannot be read off
work still in progress.

Every outcome the driver reports is carried forward, not only the successes.
A phase that kept the successes alone cannot tell a clean run from one where a
required ceremony failed beside a passing one, and cannot see a ceremony
succeeding where the property under test is that it must not.

The pre-cutover steps name the ceremonies they must see settle one by one —
`tbtc_dkg`, `tbtc_signing`, `tbtc_heartbeat`, `beacon_dkg` and
`beacon_signing`, with `tbtc_wallet_action` added to the step whose subject is
the longest practical action. The mandate is that mixed prior/R1 tBTC signing,
DKG and heartbeat and the beacon controls all succeed below C, and neither a
family nor a work-class requirement can state that. "A tBTC threshold ceremony
settled" is satisfied by a signing alone, which leaves the DKG and heartbeat
paths into the gate undriven even though each anchors differently and refuses
separately; a fixture covering both halves of the release and both work classes
can still be three mandated ceremonies short. The heartbeat is the clearest
case: it settles like a signing and carries the inactivity penalty path the
crossing has to keep quiet, so a step that drove none says nothing about the
path most in need of the evidence. Naming the ceremonies means the step reports
on the work the mandate describes rather than on whichever ceremony the driver
happened to pick.

The homogeneous control is decided against both halves of its own name, over
the whole report, on bound records. "security-v2 controls" needs a ceremony the
driver watched complete on a transaction it originated and that left a
threshold output behind, not only permits the fleet issued — and it needs one
from each half of the release. tBTC and the beacon take their permits from the same gate
through different call paths, so a driver that only ever drove tBTC leaves the
beacon's path unexercised however many tBTC ceremonies settled; a control
covering half the release cannot support a claim made about all of it, and the
step blocks. Anything the driver reported as failed or timed out refutes the
control outright: a report is taken whole, so the half that passed cannot
record the control on its own. "with no legacy sightings" is read where a
sighting would appear — the announcer's cross-format recognition counter and
the legacy roster, summed and unioned across the whole R1 fleet — because the
legacy permit counter is about work this fleet took on, not about what it saw.
The straggler is quarantined before this step runs, so a recognition or a
roster entry during it means the fleet was not homogeneous.

Both halves of that report are what a step reads to decide work was offered at
all. A driver call that exited nonzero, that was never supplied, or that named
no transaction leaves the fleet in exactly the state a fleet nobody asked is
in — unchanged permit counters, an untouched roster — so a step whose contract
is that the gate *refused* something requires a clean exit and at least one
named transaction before it treats its readings as a refusal. The clock-failure
and quiescence probes distinguish the two: a driver that failed while
attempting the offer is recorded as a broken instrument naming its exit status,
not as a gate nobody challenged.

A clean offer is still not a refusal, though — an unchanged permit counter is
equally the shape of work that never reached the node at all. So the quiescence
step also requires the node's *own* account: the gate counts every refusal it
makes, and counts it per ceremony, so the quiescing node's refusal total must
move and a per-ceremony counter must move with it. That is what puts the
refusal on the node rather than on the prober's inference, and what names which
ceremony was refused; a total that moved with no ceremony behind it blocks,
because a refusal a release cannot attribute to a ceremony is not evidence
about that ceremony.

The rollback drain reads the fleet's in-flight security-v2 permits at the
moment the stop is issued: a `compose stop` that returns zero over an idle
fleet evidences that stopping works, not that a node holding protocol work
drains rather than dropping it. It also reads *what kind* of work was in
flight, from the driver's `originated_ceremonies` — a permit total counts
ceremonies without distinguishing a threshold round from a Bitcoin wallet
action, and the two fail differently when a shutdown interrupts them: a
threshold ceremony loses a share and can be re-run, a wallet action can leave a
Bitcoin transaction the fleet has already signed for. A rollback authorized
over one class says nothing about the other, so both must be in flight at once.

Then every permit is followed to an outcome, per node and per piece of work
rather than in aggregate. A fleet total of zero after the drain is equally
produced by permits that finished and by processes that exited holding them,
and the difference is exactly the state a rollback restores onto. Each node's
permits at the stop must therefore land somewhere a later reader can see:
completed, evidenced by that node being observed without them, or
force-canceled at the quiesce deadline — which the gate counts and which the
offline audit must have written a quarantine record for. A force-cancel with no
quarantine record behind it is in-flight state the rollback would restore onto
with nothing describing it, and an unreadable counter blocks rather than
subtracting like a zero, which is how a permit nobody could account for would
otherwise disappear from the sum. The records must also be *enough* of them:
one record does not describe three abandoned permits, so a count short of the
force-cancels leaves the difference unaccounted for and refutes the step.

The permits and the work must be the same population before any of that means
anything. Each node's held count is compared against the pieces of work the
driver said it put on that node, and a node holding more permits than there was
work to hold them for — or fewer — blocks: an outcome for one piece of work
reconciles no particular permit when the two accounts are of different sizes,
which is how one reported result came to stand in for however many permits
happened to be outstanding.

The quarantine records are read the same way. DKG records retain the seed hash
as their chain-work ID and the member index as their local permit ID, and are
matched one-to-one rather than projected down to ceremony and block. Thus two
memberships on one node at one anchor remain two records, and a record for a
permit this drain never put on that node refutes the step instead of padding
the count. Records are filtered by the instant the stop was issued because a
quarantine namespace accumulates: records an earlier interruption wrote are
still there, and a bare count lets state from a run nobody is reconciling stand
in for permits this drain abandoned. The driver's own work classes are
translated into the gate's ceremony vocabulary for that comparison — every
non-heartbeat wallet action is gated as a signing ceremony, and the beacon's
signing class is its relay signing — because otherwise work that has a record
would appear to have none.

Neither is a permit simply "completed" because the gauge holding it fell.
Being gone is what a ceremony that finished and a process that exited holding
one both look like from outside. So the driver is asked, once the drain is
over and the outcomes exist to be read, what became of the work this gate
originated — the `rollback-terminal` phase — and every piece of that work must
have reached a terminal outcome of its own or appear in a fresh quarantine
record. Permits that were not force-canceled reconcile against the outcome of
the work they were issued for rather than against the gauge; a gate that never
asked, a terminal report from a driver that exited nonzero, and an outcome for
work this drain never originated all block rather than passing.

The single-release quiescence gate is decided the same way, for the same
reason. It retains the work the node was holding when the stop was issued —
which pieces, that the node's permit count matches how many there were, and
that the node's own gate named those same permits — and asks the driver in a
`quiesce-terminal` phase what became of each once the drain is over. A held
permit whose work never reached an outcome is a permit the process took with
it, and that is indistinguishable from completion in every counter the node
publishes. Work that ended by giving up inside the grace blocks rather than
passing: this gate audits no quarantined state, so a ceremony that exhausted
its retries evidences neither that it was allowed to finish nor that what it
left behind is accounted for.

Its legacy half needs a permit the gate issued on the legacy side of C and is
still holding long after the crossing, which nothing originated at that point
in the run can be. So the driver is asked for it in a `quiesce-legacy-seed`
phase while the fleet is still below C, and the node's own gate is read there:
the permits it reports holding must include the ones the driver named. A driver
that merely claims a below-C anchor for work it originates after the crossing
is claiming exactly the thing the control exists to observe. The drain is then
required to happen while a permit of the other mode is live on the same node —
a gate draining a single population never has to keep the two modes apart,
which is the fence quiescence is for.

That second population is held to the same standard as the first, because the
gate's promise covers every permit it was holding and the gate asks that both
live modes finish or enter audited quarantine. So the `quiesce-legacy-inflight`
phase must name the work it puts in flight beside the seeded permit, that work
must be anchored on the other side of C from the drained population — a second
population on the same side exercises no fence — the node's own gate must
report holding exactly those permits for that mode, and the
`quiesce-legacy-terminal` phase must report an outcome for every one of them
alongside the seeded population's. A gate list that is merely non-empty says
the fence was there and nothing about what the far side of it ended up doing.

The straggler control binds its roster entry to the straggler's own operator.
The prior node publishes the address it signs as at `/diagnostics`
(`client_info.chain_address`), and that address is read off it while it is
still on the network and compared — insensitive to EIP-55 versus lowercase
spelling — against the operators the observing node's roster newly named. A
roster that moved without naming that operator is the release attributing a
legacy sighting to the wrong node, which is worse evidence than none: the name
is what a release decision would act on.

Being named is not being refused, so that control also reads what the ceremony
it drove produced. The rehearsal fleet is sized so the driven post-C ceremony
needs the straggler to reach threshold: a result that settled means either the
straggler was not refused after all or the ceremony never depended on it, and
a control that did not need the node it is about has not exercised the failure
path it claims to. A ceremony with no terminal outcome at all blocks rather
than passing — retry exhaustion is what makes "produced no threshold output"
a statement about a ceremony that finished, and the roster deltas would
otherwise be read off one still in flight. That is why the driver must say
which of the two terminations it reached rather than only that the ceremony
failed, and why the record names the transaction and the termination it
decided on.

The rollback gate's own barrier has two halves and neither substitutes for
the other. Every release candidate must be provably down, and the prior binary
must have been absent for the whole of it — so the drain runs while the prior
artifact is sampled repeatedly, from before the drain starts to after it
finishes, rather than probed once at the end. A single closing probe is
satisfied by a prior binary that participated for all of quiescence and stopped
a second before the probe, which is exactly the sequence the barrier forbids.

"The prior binary" is daemon-wide too, for the same reason "every release
candidate" is, and each sample takes two readings of it. The node probe answers
whether the prior service *this project* staged is serving; the daemon
enumeration answers which containers anywhere were created from the prior
image, including ones this project neither named nor started. Neither reading
subsumes the other: a prior container left by another gate's project — or
started directly under no compose project at all — is invisible to a probe
keyed on this project's service name while watching the same rehearsal chain,
and a process still answering its client-info port after the daemon called its
container stopped is invisible to the enumeration. A prior container is counted
as participating when it is running and can still reach anything, quarantined
when running and reaching nothing, and its unreadable state blocks rather than
passes. Reachability is read from the container's network mode beside its
network map, because the map alone answers it backwards in both directions: a
container run with `container:`/`service:` mode owns no network entry precisely
because it holds another container's stack, and Docker lists `none` in the map
like any other network, so genuine isolation does not present as an empty map.
As on the candidate side, an enumeration that cannot see this project's own
staged prior container blocks: an empty active set read from a blind
instrument looks exactly like a barrier that holds.

"Every release candidate" is daemon-wide, not this project's two services. A
rollback rehearsal runs after a cutover rehearsal, and the cutover fleet is a
fleet of the same candidate artifact watching the same rehearsal chain: a
distinct compose project is a distinct namespace, not a distinct chain, so a
candidate another gate left running would go on submitting against the same
contracts while the prior binary was released beside it. The barrier therefore
enumerates every container on the daemon that was created from the candidate
image or belongs to any `pr4109-*` project, and requires each one to be stopped
or reaching nothing, read the same way. Attachment comes from the daemon
rather than from the node's own HTTP surface, because a candidate whose
client-info listener died while its protocol stack kept running answers
nothing and is still on the network; conversely a service that does answer is
promoted back to active whatever the daemon believes, since a node serving
requests is participating. An enumeration that cannot see the containers the
asking stage itself created blocks rather than passing — an empty active set
read from a blind instrument looks exactly like a barrier that holds. The
cutover stage closes by stopping its own fleet and recording the same verdict,
and the workflow stops that project again before dispatching the rollback
gate, so a single-release stage that failed halfway cannot leave the next gate
measuring a barrier against a fleet nobody accounted for.

The second half is the offline state audit reporting `rollback_barrier_ready`
for every snapshot: an all-down fleet says two releases cannot write the same
state at once, not that the state they left is safe to roll back onto. Those
snapshots are captured here, out of the containers the drain stopped, with
the storage path read off each container rather than restated — a supplied
snapshot is only a claim about what the fleet left behind, and an older
capture or another node's audits exactly as cleanly. The audit's result is
taken as a whole: its output path is cleared before it runs, so an earlier
manifest cannot stand in for one this run never produced, and a nonzero exit
refuses regardless of what the manifest claims, because the tool also exits
nonzero on an inconsistent namespace — a refusal its ready flag does not
carry. The prior binary is started only when both halves hold; every R1 node
down with an audit that authorized nothing records a blocked step and starts
nothing.

`compose.rehearsal.yaml` is the fleet shell: one prior node (no gate — the
deliberate straggler) and two R1 nodes with the non-mainnet
`--protocolParticipation.cutoverBlock` override and persistent volumes. Each
service mounts `KEYSTORE_DIR/<service>/` read-only at `/mnt/keystore` and
starts with `--config /mnt/keystore/config.toml`; that per-node config must
carry the rehearsal contract addresses, the key file path under
`/mnt/keystore`, and storage directory `/mnt/storage` (the persistent
volume). The fleet spans two networks: the internal `rehearsal` network
carries inter-node protocol traffic and evidence probes with no host
publication of any port, while `chain-egress` exists only so nodes can reach
the external `ETH_WS_URL` endpoint.

Every accepted rehearsal run must produce an evidence record conforming to
`rehearsal-evidence.schema.json`: exact source SHA, per-architecture image
digests, chain ID and C, the sha256 of the reviewed `release-manifest.json`
the fleet's termination grace was taken from and the grace value itself,
per-stage canonical/callback blocks, permit modes, gauge snapshots,
transaction hashes, and non-secret state checksums. Screenshots alone are
insufficient. `./rehearse.sh validate-evidence` checks every record under
`EVIDENCE_DIR` against the schema (ajv pinned to exact versions) and
requires the recorded manifest hash *and* the recorded termination grace to
equal the checked-in manifest's — the hash alone would accept a record that
names the right manifest while claiming the fleet ran under some other
grace — so an admissible record links the termination-grace record to the
exact artifact and chain identity it carries.

Admissible is not accepted. Everything above decides whether a record is one
this release may read at all — well formed, from the attested commit,
measured against the reviewed manifest — and says nothing about what it
says. A record is precisely where a rehearsal reports that a mandatory step
failed or an acceptance assertion does not hold, so a schema-valid,
correctly bound record can be exactly the evidence that a gate must be
refused. `validate-evidence` therefore asks the second question separately
against the exact gate contract. The single-release record must carry its 13
named stages and seven named assertions; rollback must carry its ten stages
and six assertions. Every entry occurs exactly once and in execution order,
unknown entries are rejected, and every assertion must cite its designated
passing stage rather than any convenient passing step. Single-release must
also name the reviewed work-driver digest; rollback must name both that digest
and the reviewed rollback-evidence-generator digest. Any recorded failed step
or refused assertion, in any record in the directory, exits `FAIL`; anything
missing, duplicated, misbound, blocked, or produced without its required
reviewed instrument exits `BLOCKED`. Only the complete exact contracts are
evidence of satisfied gates. A passing record beside a failing one accepts
nothing. The in-process emitter applies this same contract to the record it
just wrote before a rehearsal is allowed to print success.

Those comparisons only mean something while the checked-in manifest is
still the compiled bounds' own manifest, so the stage refuses to measure
anything until it holds the receipt proving that. `local-proofs` writes it
under `EVIDENCE_DIR/attestation` as its last step, after every proof has
passed: `release-manifest validate` accepts the reviewed file against the
compiled bounds, `release-manifest derive` records the bounds themselves in
`derived-manifest.json`, `reviewed-manifest.sha256` names the exact bytes
that were validated, and `source-commit.txt` names the commit those bounds
were compiled from. `validate-evidence` requires all three files, the hash
to match the manifest as it stands now, and the derived bounds to match the
reviewed ones field by field — hash-matching alone would accept an
attestation and a manifest regenerated together around numbers no compiled
binary produces. Only the free-form notes and the generation stamp may
differ, and keys are canonically ordered so reformatting a reviewed
manifest cannot read as drift. The attestation lives in a subdirectory
because the record glob and the workflow's record probe both look at the
top level of `EVIDENCE_DIR` only: writing the receipt never makes a
dispatch that produced no rehearsal record look like it produced one.
Running `validate-evidence` without a matching attestation is BLOCKED, not
accepted — regenerate it by re-running `local-proofs` at the same commit.

A receipt belongs to one run at one commit, and three rules keep it that
way. `local-proofs` destroys the receipt it inherits — interrupted staging
directories included — *before* it proves anything, so a run failing at any
proof leaves nothing behind; without that, a reused evidence directory kept
whichever earlier run happened to succeed in it and the acceptance stage
read that as this run's receipt. The new receipt is built beside its
destination and published by a single rename, so a reader sees a complete
receipt or none, never a half-written one or parts from two runs. And the
receipt carries the commit the binding check *proved* rather than the raw
stamp — `build-image` mode verifies a tree that legitimately diverges from
`HEAD`, so the raw stamp would call the very tree it just accepted `-dirty`
— which `validate-evidence` then requires to equal both its own
`PR4109_EXPECTED_SOURCE_COMMIT` and every record's `source_sha`. A receipt
taken at one commit can otherwise admit records from another whenever the
manifest bytes did not change between them, since the hash and bounds
comparisons have nothing to see in that case. Anything but a clean 40-hex
commit — a `-dirty` stamp, the `unknown` of a run outside a checkout — is
refused outright, and `validate-evidence` verifies its own source binding
like any other proof stage, because the manifest, schema, and comparison
rules it judges by all come out of the tree it runs from.

The validator proves itself before validating anything:
`test-validate-evidence.sh` drives the stage over fixture records — correct
binding, wrong hash, wrong grace, wrong source commit, missing binding
fields, malformed timestamp, empty record set — over incomplete and malformed
gate contracts — a one-stage passing subset, a duplicate stage replacing a
required one, an unknown assertion, a true assertion borrowing an unrelated
passing stage, missing required release inputs — the reviewed instruments and
the archived dependency review alike — and an emitted one-stage run — over correctly bound records whose *outcomes* deny the gate — a failed
step, a refused assertion with every step passing, a step that never executed,
a failure alongside an unexecuted step, and a failing record sitting beside a
passing one — over fixture attestations —
absent, incomplete, a leftover staging directory, taken over other manifest
bytes, contradicting the reviewed bounds, taken at another commit than the
run is bound to, taken on a divergent tree, and one differing only in
notes, stamp, and key order — and over a divergent tree the stage must
refuse to judge from, and the stage runs that self-test first on every
invocation. It also drives the fleet-identity capture the container stages
open with, over fleets whose nodes disagree with each other, whose revision
is not the commit the run is bound to — foreign, abbreviated, or absent —
and whose armed cutover block is not the rehearsed C; and it resolves every
helper those stages name in command position, because neither stage runs
anywhere but a real rehearsal and a call site left pointing at a renamed
function otherwise surfaces there.

The step verdicts those stages reach are proved the same way. The clock,
quiescence, and straggler decisions are functions over their observation
slots that touch no fleet, so the self-test drives them against constructed
readings: an unchallenged permit counter, work that never reached the gate, a
partial cancellation behind a drained and behind an unreadable active count,
a permit issued and closed between two samples, permits never seen at zero, a
mismatch nothing recognized as cross-format, a cross-format sighting that
entered no roster, and unreadable refusal, issuance, and forced-abort
counters. A ladder this layered is exactly the kind that goes on passing on a
proxy for the property until something can exercise it directly. The daemon
is a seam in the same way: the prior-container staging and the storage
capture run against a fixture daemon, over a container that came up running,
a create that produced nothing, a container built from other bytes, a live
node, a missing and a doubled volume, a failed copy, and an inherited capture
— and the audit against a tool that refused while a ready manifest sat at its
output path, and one that wrote nothing at all.

The chain identity is an observation too. The client publishes
`protocol_participation.ethereum_chain_id` — the chain id its own endpoint
returned when the chain handle was built, checked there against the configured
network — and the identity capture requires every R1 node to report the chain
the record is written against. A cutover block is a count on one chain, so a
fleet pointed at another chain crossed a different schedule and every block,
crossing, and reconciliation in the record would be attributed to a chain the
fleet was never on. The supplied `CHAIN_ID` is now what the observation is
checked against rather than what the record asserts, and a fleet that will not
name its chain cannot be evidenced at all. The receipt lifecycle is proved
through `stage_local_proofs`
itself rather than through the invalidation function alone: a reused
evidence directory is given a valid inherited receipt, the stage's proof
seam is failed the way any proof failure fails it, and the case requires
that the receipt was already gone when the proofs started, that none
survives the failure, and that the acceptance stage is blocked afterwards.
Moving the invalidation anywhere later in the stage, or dropping it, fails
those cases. Its cases run against throwaway git checkouts it creates, not
against the working tree, so every verdict is the same mid-edit on a
workstation and on a bound CI dispatch. The
`cutover-rehearsal` workflow (manually dispatched, in
`.github/workflows/cutover-rehearsal.yml`) runs the local proofs, the
static analyzers, and the contracts build/test on every dispatch — and the
container preflight when the image digests and chain inputs are supplied.
Each stage's log is archived in a per-SHA artifact whether the stage
passes or fails, and the per-SHA name is backed by an in-stage proof, not
just labeling: the workflow hands every proof stage the dispatched SHA via
`PR4109_EXPECTED_SOURCE_COMMIT`, and for the build-image stage it mounts
the checkout's `.git` and `scripts/` read-only into the container
(`.dockerignore` keeps both out of the build context) and sets
`PR4109_SOURCE_BINDING_MODE=build-image`. Under that mode `rehearse.sh`
accepts exactly the image's documented construction and nothing else.
First it restores the commit's own `.gitignore` files — only where absent,
byte-exact from the commit under verification, so restoration can mask
nothing while a tampered ignore file keeps its modified status — because
the image drops every root dotfile and would otherwise report its own
gitignored build outputs (the `keep-client` binary, the `tmp/contracts`
artifact trees) as untracked noise. Then every remaining status line must
be explained: a deletion only for a path `.dockerignore` keeps out of the
context (honoring the `.clusterfuzzlite` negations — those files must be
present; no context-excluded path holds Go code the proof stages compile),
and the families the image regenerates from published artifacts
(`**/gen/**/*.go` and `**/gen/_address/*`, minus the negated `gen/pb/*.go`,
`gen/gen.go`, and `gen/cmd/cmd.go`, which the final `COPY` overwrites with
committed bytes — the committed protobuf code the tests compile can never
differ) are never accepted as found: each one is restored byte-exact from
the dispatched commit — `git show` against the read-only-mounted `.git`,
whose `HEAD` was already proven equal to the dispatched SHA — before any
test compiles it, with the pre-restore image hash recorded for forensics.
Untracked files and any other status are always fatal, a path that cannot
be restored is fatal, and the whole tree is re-checked after restoration:
anything left beyond the context-excluded absences fails the stage. The
resolved contract artifact tarballs under `tmp/contracts` — name, exact
version, sha256 — are still recorded as the image build's input identity
(the workflow pins the `ENVIRONMENT` build-arg from its
`artifact_environment` input instead of riding the Makefile's implicit
default), but they are forensic context only: whatever npm tag or version
the image was built from, the bytes the proof stages compile are the
dispatched commit's bytes by construction. The verifier is itself under
test: `test-source-binding.sh` drives it through checkout- and
image-shaped throwaway repositories — clean image, expected absences
alone, arbitrary bytes in every regenerated family proven replaced on disk
by the committed bytes, an unrestorable path, injected or deleted source,
tampered committed generated code, missing metadata, SHA mismatch — and
runs both as an early workflow step on the runner and inside
`local-proofs`, so its verdicts land in the archived evidence.
`./rehearse.sh verify-source-binding` runs the binding check alone and
records it under `EVIDENCE_DIR`.

Which absences that verifier may explain away is decided by a
classification of the build context written out in `rehearse.sh`, and a
hand-written mirror drifts silently whenever the thing it mirrors changes.
Both `local-proofs` and `shell-analysis` therefore hold it to the commit's
own `.dockerignore`, compiled the way the build daemon reads it — comments
and blanks dropped, negations split off, patterns path-cleaned, `*` stopping
at a separator, `**` spanning whole segments, last match winning, a path
excluded when it or any ancestor matches — and compared against the script's
verdict for every tracked path. The rules are read from the commit rather
than from disk, because inside the build image the file is one of the paths
its own `.*` rule kept out. A path the script calls context-excluded while
`.dockerignore` keeps it in the context is the dangerous direction and
always fails: build-image mode would otherwise explain that file's absence
as the image's construction and accept a tree missing it. The opposite
direction is safe but still drift, and is tolerated only for the families
the image regenerates by design — the ones the verifier restores byte-exact
rather than explains away. A pattern construct the compilation does not
model, an absent `.dockerignore`, and one carrying no rule at all each fail
closed. `test-source-binding.sh` proves all of it against throwaway trees
carrying the checked-in rules and deliberate drifts of them, and refuses to
build a drift case out of a filter that removes no line, so a case cannot
pass because the rule it targets was renamed.

Which ignore file the build reads is itself decided elsewhere: the builder
selects `<dockerfile>.dockerignore` when the commit carries one and the root
`.dockerignore` only otherwise, and which Dockerfile that is comes out of the
rehearsal workflow's build step, not out of this scaffold. So the identity is
read from that step rather than restated beside the classification — the
single `docker/build-push-action` step's `context` and `file` inputs, taken
from the commit under test. A constant restating them would go stale the
moment the build step moved, silently and in the direction where the mirror
keeps checking itself against rules the build has stopped applying. Every
step shape the resolution cannot read the way the workflow parser does is
refused by name rather than guessed at: a context that is not the repository
root (the classification is written over repository-relative paths), an unset
context (the action's default is the Git context, not this checkout), a
Dockerfile named by a workflow expression or resolving outside the context or
absent from the commit, inputs written as a flow mapping, and more or fewer
than one build step.

The rehearsal workflow writes its evidence into the workspace root rather
than the script's own default, and every proof stage refuses to run on a
tree that diverges from the dispatched commit — untracked files included —
so `/rehearsal-evidence/` is an ignore rule the repository's root
`.gitignore` carries alongside the script-local one. Without it a stage's
own log would count as divergence and fail the stage that wrote it.

Everything above runs only when somebody dispatches it, which is the wrong
gate for the checkers that decide what may become release evidence. The
`cutover-scaffold-lint` workflow
(`.github/workflows/cutover-scaffold-lint.yml`) is what runs without being
asked: on every push and pull request touching the scaffold it runs
`./rehearse.sh shell-analysis`, which puts shell syntax, ShellCheck,
actionlint, the build-context mirror check, and both validator self-tests over
every change to `rehearse.sh`, to either self-test, and to the workflows
themselves. Whether failing it also *blocks a merge* is a setting outside this
repository, and one whose standing is recorded — not assumed — under "An
enforcing ruleset behind the scaffold gate" in **Hard external dependencies**.
Its path filters cover the build inputs the trust model is derived
from as well as the scaffold's own files — `.dockerignore`, both ignore files
the build could select, the root and nested `.gitignore` rules, `Dockerfile`,
and the root and per-package `Makefile`s — because each of them decides what
the verifier accepts just as directly as its own code does, and a change to
any of them can widen what an image tree is allowed to be missing without
touching a line under `scripts/`. It builds no image and runs no Go suite, so
it is cheap enough to require.

Those filters decide when this gate runs at all, so neither they nor the list
they are measured against is maintained by hand: a build moved onto another
Dockerfile takes its ignore file with it, and a filter list left behind would
leave every later change to that file ungated while the mirror check went on
passing, on a file nobody was told had changed. `shell-analysis` therefore
enumerates the required inputs out of the commit under test — the three
workflows, the resolved Dockerfile, the ignore file that Dockerfile selects,
the root `.dockerignore`, every file under this directory, and every committed
`.gitignore` and `Makefile` — and requires each `push` and `pull_request`
trigger to run on all of them, or to carry no filter at all, which runs on
everything and covers everything. Adding a `gen/Makefile` or a nested
`.gitignore` therefore extends what the gate must cover without anyone
remembering to say so.

The list is read the way the workflow parser reads it, in order with the last
matching entry deciding, so an entry listed and then negated further down is
not coverage; a pattern construct this scaffold has no reading for is refused
rather than guessed at. A `paths-ignore` list, an empty filter list, and a
workflow reachable only by dispatch each fail closed.

Trigger shape is held to the same standard, because a restriction there is
invisible to a check that reads only paths and leaves the same hole. A `push`
trigger fires only after a branch has already moved, so a `pull_request`
trigger is required outright and refused if it carries `branches` or
`branches-ignore` — every restriction of it exempts some merge — or if its
`types` list drops one of `opened`, `synchronize`, `reopened`: without
`synchronize` the gate runs when a pull request opens and never again on what
is pushed into it afterwards. The `push` trigger's own `branches: [main]` is
accepted, since the `pull_request` trigger beside it is what holds the merge.

All of that says when the gate runs and none of it says that reaching it runs
anything, so the invocation is placed too: a workflow firing on every change
to every input while its job no longer calls `rehearse.sh shell-analysis` is
the same ungated state spelled differently, and it satisfies every rule above.
`shell-analysis` requires exactly one such invocation — two would leave it
unable to say which placement the rest of the reading belongs to — and refuses
an `if:` on either that step or the job around it, along with a
`continue-on-error` on either that is not spelled `false`. A condition is
refused rather than evaluated: nothing here can tell which runs it would hold
for, and a gate whose reachability rests on a condition nothing reads is not
one this scaffold has proved reachable. A condition on some *other* step is
untouched — the evidence upload runs under `if: always()` precisely so a
failing analyzer's log survives.

Matching text is not a run, so the invocation is read rather than found. It is
looked for only in a step's `run:` body, because that is the only key that
runs anything: the same text in a step name, an `env:` value or an action's
inputs labels a step that can do nothing at all. Inside that body the shell is
read as the shell takes it — lines joined across a trailing backslash, so an
invocation continued over two of them is one command — and the command has to
be the analysis itself and the *last* thing the body does, since a step reports
its last command's exit status. Around it, the shapes that would leave the text
running while the result went nowhere are refused by name: a pipeline, a `&&`
or `||` chain, a `;` list, a background `&`, a redirection, a command
substitution, a subshell, a compound-statement keyword, and the builtins that
decide what the shell does with the lines after them — `set -n` reads a body
without executing a line of it. Anything after the invocation is refused for
the same reason: a trailing `echo` is what a failing analysis would then be
reported as.

The two ways a body runs under something other than the shell it was written
for are held the same way. A step-level `shell:` is accepted only spelled
`bash`, the runner's own default: `shell: cat {0}` leaves every line exactly
as it was and executes none of them. `defaults:` — on the job or on the
workflow — sets that same thing further out and is refused outright rather
than followed. Workflow expressions inside the body are read too, because the
runner substitutes their values before the shell parses the line: only the
runner's own contexts (`github.workspace`, `runner.temp` and their siblings)
are accepted, and an expression carrying pull-request text is refused, since
its value is what would decide the command.

Reading the command is still not reading the run. The same invocation, spelled
character for character as the checked-in one, reaches something else entirely
when the environment or the tree around it changes, and none of that touches a
line the paragraphs above read. So four more shapes are refused:

- **`env:`**, on the step, the job or the workflow. The runner writes those
  names into the step's shell before it parses anything, and a `BASH_ENV`
  there names a file that shell sources first — where a function can be
  defined under the entrypoint's own name. The accepted command word then
  resolves to that function and returns whatever it says. An assignment
  written onto the invocation itself (`BASH_ENV=… ./rehearse.sh
  shell-analysis`) is the same interception with no key to hold it, so the
  assignments ahead of the command are read rather than skipped: only
  `EVIDENCE_DIR`, the one environment name this entrypoint documents itself as
  reading, is accepted there.
- **`working-directory:`**. The invocation is a relative path; resolved from
  another directory it names another file, and what was proved to run is an
  analysis somewhere else.
- **`container:`** on the job. The image decides both what `bash` is and what
  stands at the entrypoint's path, and nothing here reads images.
- **a preceding `run:` step in the same job.** It needs no key on the analysis
  step at all: it can write another file over the entrypoint in the checkout,
  or append `BASH_ENV` to `$GITHUB_ENV` for every step after it.

What none of that proves is that a run happened, or that a run reporting
success ran this file. Everything `shell-analysis` reads is the head commit's —
the workflow, the steps around the invocation, the entrypoint itself — and the
check that would notice the invocation being deleted lives *behind* that
invocation: a commit that removes the step also removes the run that would have
objected.

**A branch-protection rule requiring the `scaffold-lint` check does not close
this**, and this scaffold does not claim it does. That rule requires a
conclusion under a job name, and the job producing it is defined by the same
head commit under test: a commit keeping the name while its job runs something
else reports success and merges. The four refusals above narrow that to shapes
this parser reads; they are a narrowing and not a closure, and shapes outside
them remain. A preceding `uses:` step runs code from another repository and
reaches `$GITHUB_ENV` and the checkout just as directly, and it is accepted
here only because refusing it would refuse the checkout the analysis needs to
read anything at all. An ordinary command ahead of the invocation in the
analysis step's own body is accepted for a narrower reason: the words ahead of
the invocation are read for the shell they open and nothing else, and a `cp`
over the entrypoint opens none — after which the accepted final command runs
whatever the copy left at that path. Both are pinned as accepted cases in
`test-source-binding.sh`, because a boundary a reader has to infer from the
absence of a case is one the next rewording moves.

The control that does close it has to be defined where the pull request cannot
edit it, which is why it cannot be **this workflow under a rule**: a
`workflows` ruleset entry names one source repository and one path, and an
entry naming this file names something every pull request here can rewrite.
What closes the boundary is a **separate workflow, sourced from a repository no
pull request into `keep-core` can write to, pinned by commit SHA, and carrying
its own copy of the analysis** rather than calling back into the commit under
test for it. This file stays advisory however that is configured. The
requirement is tracked as an outstanding external dependency, with what was and
was not checkable from here, under "An enforcing ruleset behind the scaffold
gate" in **Hard external dependencies**.
`shell-analysis`'s own log says exactly that rather than claiming otherwise: it
reports what the commit under test says, and names this file for the rest.

The same reasoning covers the other claim this scaffold makes about work it
did not do itself. `solidity-proofs` says its evidence is
`contracts-ecdsa.yml`'s `contracts-build-and-test` job's evidence, and that
holds only while the stage and the dispatch that provisions it run the Node
release that job pins — a release picked precisely because another one broke
hardhat's compile artifacts. So it is read out of that job rather than
restated beside the claim: `shell-analysis` resolves it from the named job
(not from the workflow around it, whose other jobs pin other releases) and
requires the rehearsal workflow's own `solidity-proofs` setup-node to match,
while the stage itself blocks on any other interpreter. A pin loose enough
for the runner to choose, one decided by a workflow expression, a job that
sets up Node twice or not at all, and a renamed or absent job each fail
closed. That is why `contracts-ecdsa.yml` is one of the lint's path filters:
a bump there touches no line under `scripts/`.

On a hosted runner the per-node keystore comes from the
`REHEARSAL_KEYSTORE_BUNDLE_B64` repository secret: a base64-encoded tar.gz
whose top level holds one `<service>/` directory per rehearsal node, each
with its `config.toml` and rehearsal-only key material. Generate it from a
prepared `KEYSTORE_DIR` with `tar -cz -C "$KEYSTORE_DIR" . | base64`. The
bundle MUST contain throwaway rehearsal keys only — never production
operator keys — and the dispatch reports `BLOCKED` when the secret is not
provisioned. The companion `REHEARSAL_KEEP_ETHEREUM_PASSWORD` secret carries
the key files' password.

The rest of what a container rehearsal needs is chain-side, which is to say
outside this repository, and arrives the same way. The dispatch inputs name
the artifacts and the chain: the prior, R1, and probe digests (all three
immutable — every evidence reading is a scrape through the probe, so a
mutable probe tag would leave the reading instrument outside the record's
provenance), the rehearsal chain's websocket endpoint and numeric chain id,
its JSON-RPC endpoint — the one every transaction a driver reports is
confirmed against, and which preflight refuses unless it answers with the
rehearsed chain id — the rehearsed `C`, and the Bitcoin network, prior
version, and prior revision the rollback state audit binds its verdict to. The
`REHEARSAL_CHAIN_INPUTS_BUNDLE_B64` secret carries two executables, not data:
a base64-encoded tar.gz holding `work-driver` — called with the phase name,
because the fleet only reacts to chain events and without something
originating deposits, DKG requests, and relay requests there is no ceremony to
observe — and `rollback-evidence-generator`, called once per drained node with
that node's identity audit manifest and an output directory. The evidence is
generated rather than shipped because each record must name the aggregate
checksum of the snapshot it speaks for, and that snapshot does not exist until
this run has drained the fleet; a bundle unpacked before the fleet started
could not know a checksum computed later. Both members are checked as they are
unpacked, so a bundle missing one blocks before the fleet starts rather than
halfway through a rehearsal.

An executable bit is not provenance, though, and that secret is mutable. Both
programs produce readings that become release evidence — the driver's account
of what it originated and what became of it is the terminal half of every
control that watches work settle — so a stale, replaced, or simply wrong
program manufactures an internally consistent passing account while every
check in this repository stays green. Preflight therefore hashes each supplied
program and compares it against `chain-inputs.sha256`, a reviewed control
checked in beside this file, before any node is started; a mismatch, or a
program the control does not name, stops the rehearsal. The digests are
recorded into the evidence document under `chain_inputs`, and the acceptance
stage refuses a record naming a digest the control does not pin, one carrying
chain transactions while naming no driver at all, or an otherwise complete
gate omitting a release input its contract uses. Single-release requires the
driver and the archived dependency review; rollback requires the driver and
the generator. That control currently pins the all-zero placeholder for all
three, which matches no file: no driver or generator has been written and
reviewed and no dependency review has been archived, so every dispatch that
supplies one blocks until a reviewed digest is recorded in a reviewed commit.
An unpinned control that admitted anything would be worse than an absent one,
because it would read as having been exercised.

Everything provisioned lands outside the checkout, under the runner's
temporary directory. The container stages verify their own source binding
before they emit or judge a record, and that check counts untracked files as
divergence — so a keystore or an input bundle unpacked into the workspace
would fail the very stage it was provisioned to enable. The evidence
directory is the one exception, and only because the commit's own
`.gitignore` covers it.

Storage snapshots are not among the supplied inputs. The rollback stage
captures each drained node's state itself, straight out of the container it
just stopped, into `STORAGE_SNAPSHOT_DIR`; a supplied snapshot is only a
claim about what the fleet left behind, and an older capture or another
node's audits exactly as cleanly as the real thing. Those captures hold live
protocol state — key shares included — so they stay on the runner and are
never archived. What a reviewer reads is what each capture produces under
`state-audit/` in the evidence directory: the identity manifest, the records
the generator wrote for that snapshot, and the authorizing manifest over them.

The container job is bound to the same commit as every other proof stage,
and the receipt that binds it — the local-proofs stage's attestation of the
reviewed manifest against the compiled bounds — is downloaded from that
job's artifact before any rehearsal runs, because a rehearsal that reaches
its emitter without one blocks there, in the one place a dispatch cannot
diagnose from the log it archives. The rollback rehearsal runs on whatever
verdict the cutover rehearsal reached: a refused cutover is exactly when the
rollback gate's evidence matters most. Only a failed preflight stops it,
since that means the inputs never validated and the record would be about
nothing. Both fleets are torn down and both records are archived whatever
happened.

## Release manifest: service-manager termination grace

A terminating node drains instead of dying: the first SIGTERM quiesces the
participation gate, already-started ceremonies run to natural completion, and
only the in-process backstop — `(maximum legacy completion bound + reviewed
margin) × upper block interval + RPC/processing allowance`, armed by
`quiesceBackstopDeadline` in `cmd/start.go` — forces the remainder through the
audited forced-cancellation path. All of that is useless if the external
service manager SIGKILLs the process first: the Kubernetes default grace is
30 s and systemd's is typically 90 s, both hours short of the drain a node may
legitimately need. The release manifest exists to close that gap fail-closed
rather than by hand-tuned deployment values.

`release-manifest.json` records every input of the external grace — the tBTC
and beacon completion bounds with the beacon chain configuration they came
from, the reviewed quiesce margin, the upper block interval, the
RPC/processing allowance, and the resulting in-process backstop — plus the
forced-cancellation allowance between the backstop firing and SIGKILL,
itself a compiled constant: after the forced cancellation the lifecycle
controller keeps the run context alive until every canceled permit owner
finishes its quarantine/audit cleanup and releases its permit, waiting at
most exactly that constant. Validation checks the recorded allowance against
the compiled value like every other number — never re-deriving around the
manifest's own field — so a manifest whose allowance, grace, and scaffold
values were all recomputed coherently around a different allowance is still
rejected, and a `cmd` test additionally pins the runtime wait to the
checked-in manifest's recorded allowance. The service manager counts its grace from SIGTERM delivery, but the
backstop timer arms only after the controller has been scheduled and has
quiesced the gate, the allowance timer only after the gate has closed, and
the logging and teardown run after both — so the manifest adds the compiled
process-exit headroom (`processExitHeadroomSeconds`) on top of the two timed
waits, and the external grace strictly outlasts the complete internal
shutdown sequence rather than merely equaling the sum of its timers. The
authoritative external grace is the checked sum
`in_process_backstop_seconds + forced_cancellation_allowance_seconds +
process_exit_headroom_seconds` (currently `19800 + 300 + 60 = 20160`
seconds); a lifecycle test walks a forced shutdown from the termination
instant to exit readiness and requires the controller's overhead to fit
inside that headroom. The client never reads the manifest at runtime; its
bounds are compiled in, and the manifest exists so the SIGKILL deadline is
derived from those same bounds.

The chain is enforced at three layers, each fail-closed:

- `keep-client release-manifest derive` prints the manifest derived from the
  binary's compiled bounds, and `keep-client release-manifest validate
  --manifest <path>` re-derives every number and rejects the manifest on any
  mismatch, reporting every violation at once. Because the subcommand ships in
  the client binary, the exact-image rehearsal can validate the manifest with
  the very artifact under test.
- `go test ./cmd/ -run TestReleaseManifest` pins the checked-in manifest to
  the compiled bounds and the deployment scaffold to the manifest, so a
  changed protocol constant, a stale manifest, and a drifted scaffold value
  all fail the ordinary test suite; the strict loader additionally rejects
  unknown fields, trailing content, and non-integer numbers. The
  `local-proofs` stage runs these checks under the race detector.
- `release-manifest.schema.json` describes the document shape for external
  tooling; schema validity alone is never authority — only the compiled-bound
  validation is.

`deploy/` carries the two scaffold fragments operators apply, each holding
exactly the manifest's grace: `keep-client-termination-grace.k8s-patch.yaml`
(`spec.template.spec.terminationGracePeriodSeconds`, applied with `kubectl
patch --patch-file`) and `keep-client-termination-grace.systemd-dropin.conf`
(`TimeoutStopSec` plus an explicit `KillSignal=SIGTERM`, installed as a
`<unit>.service.d/` drop-in). The rehearsal fleet carries the same contract:
both R1 services in `compose.rehearsal.yaml` set the manifest's grace as
their `stop_grace_period`, because Docker's 10-second default would SIGKILL
a draining node long before its backstop and no rollback rehearsal could
ever evidence natural completion — the prior node deliberately keeps the
default, having no drain semantics to protect. The grace is a ceiling, not a
wait — a node whose drain completes exits immediately. Changing any compiled
bound — the cleanup allowance included — requires regenerating the manifest
with `derive`, re-reviewing it, and updating every scaffold site; the `cmd`
tests refuse any shortcut through that sequence.

## Hard external dependencies

### An enforcing ruleset behind the scaffold gate

`shell-analysis` proves what the commit under test *says* about
`cutover-scaffold-lint.yml`, and it cannot prove that a run of that workflow
happened or that a run reporting success ran this analyzer — the check lives
behind the invocation it checks, and the job producing the check is defined by
the same head commit. The reading detailed under "Cutover rehearsal scaffold"
narrows the shapes a green conclusion can hide (an `env:` at any level, an
assignment on the invocation, a `working-directory:`, a job `container:`, a
preceding `run:` step); it does not close the boundary. A preceding `uses:`
step is accepted while reaching `$GITHUB_ENV` and the checkout just as
directly, and so is an ordinary command ahead of the invocation inside the
analysis step's own body: a `cp` over the entrypoint is neither a shell
construct nor a builtin, and that is all the words ahead of the invocation are
read for. Both shapes are pinned as accepted in `test-source-binding.sh`, so a
later reading of the refusals cannot quietly grow into a claim of closure.

Only a control defined where the pull request cannot edit it closes this.
GitHub's is a **ruleset rule requiring a workflow** — "Require workflows to
pass before merging", spelled `"type": "workflows"` in the API, settable at
the organisation or enterprise level. Its `parameters.workflows` is a list of
entries, each requiring a `repository_id` and a `path`, and each carrying two
optional pin fields: `ref`, documented as "the ref (branch or tag) of the
workflow file to use", and `sha`, "the commit SHA of the workflow file to
use". It replaced Actions Required Workflows, which stopped being configurable
on 2023-09-20 and became unreachable on 2023-10-18:
`/orgs/{org}/actions/required_workflows` is not the control to look for, and
whatever it answers settles nothing about the present
one. A branch-protection rule requiring the `scaffold-lint` check is not a
substitute either — it requires a conclusion under a job name that the commit
under test defines.

Because an entry names one repository and one path, the rule cannot be pointed
at `cutover-scaffold-lint.yml` and be beyond this repository's reach at the
same time: requiring that path requires a file every pull request here can
rewrite, and the run it demands is the run the commit under test defines. **The
required workflow is a different file from the gate checked in here**, and the
gate checked in here stays advisory however the ruleset is configured.

Three properties of that entry are what close the boundary, and any one
missing reopens it:

- **The source repository is not this one.** `repository_id` must resolve to a
  repository no pull request into `keep-core` can write to. The integer alone
  settles nothing a reader can check, so the record names the repository it
  resolves to.
- **The pin is immutable.** `ref` names a branch or a tag and both move — a
  push to the branch, or a tag re-pointed at another commit, changes what runs
  without changing the rule, so a `ref`-only entry pins a name and not the
  bytes behind it. `sha` is what binds bytes, and is what the record carries. A
  tag is admissible only with evidence that it cannot move: an `active` ruleset
  on the source repository whose `target` is `tag`, whose conditions select
  that tag rather than some other one, whose `bypass_actors` do not hand it
  back to the maintainers the pin exists to bind, and whose rules include
  `deletion`, `update` and `non_fast_forward`, recorded the way this one is —
  the same exact-condition reading the ruleset behind the gate gets below,
  because a tag ruleset aimed elsewhere holds nothing here either.
- **The analysis is carried by that pinned source.** A pinned workflow that
  merely invokes the head commit's `scripts/release/pr4109/rehearse.sh`
  re-inherits everything above: the analyzer it runs is still the one the
  commit under test supplies. The SHA has to bind the checker implementation
  too, and the record names the analyzer that SHA binds.

Enforcement state belongs in the record rather than being assumed from the
ruleset's existence: `enforcement` is one of `disabled`, `active` and
`evaluate`, and `evaluate` is a dry run that reports without blocking a merge.
Only `active` gates anything. The carve-out that can leave an `active` ruleset
gating nothing for the merge that matters is recorded with it:
`bypass_actors` names actors holding permission to set the ruleset's rules
aside, each under a `bypass_mode` of `always`, `exempt` or `pull_request` that
governs when that permission is available and whether the actor has to reach
for it, and `pull_request` is not the narrow one it reads as. It confines that
actor's bypass to pull requests, and a merge into `main` goes through one, so
an actor listed that way can choose to bypass on exactly the event this gate
exists for. What the record carries is that capability, not a prediction it
gets exercised: a bypass declined on one merge is still available on the next,
so each actor's type, identity and mode belong in the record whether or not
one has ever been taken. `exempt` is the mode to read hardest — the rules are
not run for that actor and no bypass audit entry is written, so it is the
carve-out that leaves no trace on the merge it lets through. `pull_request` is
applicable only to branch rulesets, which is why it cannot appear on the `tag`
ruleset the pin above leans on: a bypass actor there holds `always` or
`exempt`, and both are unconditional.
The `workflows` rule's own `do_not_enforce_on_create` is recorded beside it
but is not a second such carve-out, and reading it as one waives a gate that
is in fact still standing: it is documented as allowing repositories and
branches to be *created* when a check would otherwise prohibit it, so it
waives the rule for the creation of a ref and not for an update to one that
exists. A merge into an existing `main` is an update, and this field leaves it
gated. What it does reach is a `main` deleted and created again, which is why
the record carries it rather than dropping it.

`enforcement`, `target` and the entry's own three properties still say nothing
about *what* the ruleset is aimed at. `target` is one of `branch`, `tag`,
`push` and `repository`: it names a kind of ref, not an instance, and the
instances come from `conditions`. An organisation-level branch ruleset pairs
`ref_name` with exactly one repository selector — `repository_name`,
`repository_id` or `repository_property` — and those three do not read alike,
so a record resolving "the conditions" generically resolves nothing:

- `ref_name` is an `include`/`exclude` pair of ref names or patterns, on all
  three variants. `include` accepts `~ALL` and `~DEFAULT_BRANCH` alongside an
  explicit `refs/heads/main` and one entry matching is enough; `exclude` fails
  the condition when any entry matches, so it takes back what `include`
  matched.
- `repository_name` is that same shape over repository names and patterns,
  `~ALL` accepted, plus a `protected` flag that governs renaming the targets
  and says nothing about what the ruleset is aimed at.
- `repository_id` is not that shape at all. It carries a `repository_ids`
  array of integers and one of them matching is the entire test: there is no
  repository-level `exclude` to take that back, and no `~ALL`. What it needs
  is the resolution the integer withholds — the ID read back as
  `threshold-network/keep-core`.
- `repository_property` is an `include`/`exclude` pair over `name` /
  `property_values` / `source` objects rather than strings, and its `include`
  is conjunctive where the others are disjunctive: *all* listed properties
  must match, while `exclude` still fails on any. It therefore aims at
  whatever set of repositories currently carries those values — a set this
  one can enter or leave without the ruleset changing — so the record has to
  name the properties and values, not merely which selector was used.

So an `active`, unbypassed, externally SHA-pinned entry carrying its own
analyzer can hold every property above and gate nothing here, by being aimed
at another repository or at every branch except this one — and it reads, in a
record naming only the target, as though it closed the boundary. The record
therefore resolves the conditions instead of reproducing them: the exact
`conditions` object, the repository selector in use carrying the evidence that
resolves it to `threshold-network/keep-core` — the ID read back to a
repository, or the property names and values read back to this repository's —
and that `ref_name` matches `refs/heads/main`, by pattern, by `~ALL`, or by
`~DEFAULT_BRANCH` while `main` is the default branch, with `ref_name.exclude`
not removing it again.

Standing, checked empirically on 2026-07-28:
`GET /repos/threshold-network/keep-core/rulesets?includes_parents=true`
returns an empty list. That is the informative probe — `includes_parents`
defaults to `true` and pulls in rulesets configured at higher levels that
apply to this repository, and GitHub filters only `bypass_actors` by the
caller's permission — so from outside the organisation this is the strongest
available signal, and it is a negative one: no ruleset, repository-level or
inherited, applies here. `GET /orgs/threshold-network/rulesets` returns 404
without `admin:org`, and GitHub answers 404 rather than 403 for organisation
resources a caller cannot see, so on its own it distinguishes an absent
ruleset from an invisible one not at all.
`GET /repos/threshold-network/keep-core/branches/main/protection` returns 404,
which for that endpoint likewise means either no protection or no admin rights
and so settles nothing either way.

Until an organisation admin configures such a ruleset, **the gate is
advisory**: a commit deleting `cutover-scaffold-lint.yml` deletes its own
enforcement silently, and a green `scaffold-lint` conclusion is evidence that
something under that name succeeded, not that this analyzer ran. Evidence that
rests on the scaffold's own checkers having judged a change should be read
with that in mind. Unblocking is a configuration change plus the record, not a
code change here, and the record has to name the ruleset's id and name, its
target, its exact `conditions` object together with the evidence resolving
that object's repository selector to this repository and its `ref_name` to
`refs/heads/main`, its `enforcement` — which must read `active` — its
`bypass_actors` with each actor's type, identity and `bypass_mode`, and the
rule's `do_not_enforce_on_create`, and, for the `workflows` entry, the
`repository_id` together with the repository it resolves to, the `path`, the
`sha` pinning it — or, for a tag, the tag together with the ruleset holding
that tag immutable — and the analyzer that pin binds. A record naming this
repository as the source, carrying a `ref` where the `sha` belongs, or leaving
the conditions unresolved, records something that does not close the boundary.

### Dual-mode tss-lib fork and independent-review gate

R1's per-ceremony compatibility bundle covers all four wire- and
transcript-sensitive decisions (`pkg/protocol/compatibility`): the
announcement session-ID formats, the ECDH symmetric-key derivation, the G1
hash-to-point mapping, and the tECDSA proof-transcript configuration. The
bundle travels from the participation permit into every tECDSA DKG and
signing party (`pkg/tecdsa/dkg`, `pkg/tecdsa/signing` take the bundle
explicitly — there is no default), and a repository check
(`pkg/protocol/compatibility/transcript_ownership_test.go`) fails the build
tests if a call site bypasses it.

The build resolves exactly one `github.com/bnb-chain/tss-lib` replacement:
the immutable `threshold-network/tss-lib` revision
`d847ce0030193ccf5dbec0097571dcce5a2a5cf6` in `go.mod`. That revision adds an
explicit per-party `legacy`/`security-v2` transcript mode with no default and
freezes it when an ECDSA local party is constructed. Legacy reproduces the
historical untagged challenge formulas; security-v2 retains the
session-bound, domain-tagged transcript and requires a ceremony nonce. The
mode-independent validation and memory-safety guards remain active on both
paths.

The dependency suite pins the historical DLN, range-proof, and Bob-proof
challenge formulas directly and completes homogeneous keygen and signing in
both modes. Its full test suite, focused race suite, and `go vet ./...` pass
for the pinned commit. In keep-core, the compatibility bundle is now the sole
owner of `SetProtocolMode` and session-nonce configuration, the temporary
legacy refusals are removed, and the formerly skipped homogeneous legacy DKG
and signing cases run complete real transcripts after a pre-cutover anchor.

Independent cryptographic review is still a release gate, and it is a gate on
*evidence acceptance* rather than on execution. The commit is published on the
dependency repository's `codex/dual-mode-transcript` branch and proposed for
review in `threshold-network/tss-lib#9`, but this repository does not contain
an archived independent review record for it.

Whether that review exists changes nothing about what a rehearsal can run or
observe — the immutable images and the work driver decide that — so the four
mixed-prior/R1 legacy-image steps of the `single-release` gate execute
whenever those artifacts are supplied, and record what they observed. What the
review decides is whether the resulting record is release-authoritative, and
that is settled once, at acceptance:

- `PR4109_TSSLIB_REVIEW` names an archived review record. It is never
  executed. It is bound twice — its bytes must hash to the `tsslib-review`
  digest reviewed in `chain-inputs.sha256`, and the document must name the
  exact dependency revision `go.mod` resolves — because either binding alone
  admits a review of other code.
- The `single_release` acceptance contract requires `tsslib_review_sha256` in
  the emitted record's `chain_inputs`. A rehearsal that ran every mandatory
  step without a review record produces a complete, admissible record that
  acceptance still refuses.

`chain-inputs.sha256` pins the all-zero placeholder for `tsslib-review`, which
matches no file, so supplying a review record blocks until a real digest is
recorded there in a reviewed commit. The implementation, immutable dependency
pin, and in-repository acceptance evidence exist; independent review and
exact-image execution remain.

## clientInfo.port 9601 compatibility smoke matrix

### What is proven where

| Layer | Proof | Runnable |
|---|---|---|
| Port resolution (flag/TOML precedence, both explicit-zero paths, custom port) | Go unit/config tests | ✅ locally, no Docker/chain |
| Port → listener decision (`0` disables, nonzero enables) | `pkg/clientinfo` unit tests | ✅ locally, no Docker/chain |
| Runtime image bakes the 9601 default | `clientinfo-port-smoke.sh image-default-check` | ✅ Docker only, no chain |
| Container listens on 9601 / custom, serves meaningful `/metrics` | `clientinfo-port-smoke.sh listener-matrix` | ⚙️ needs Docker **and** a chain endpoint + operator key |
| Testnet scrape from the real monitoring host, 3 consecutive intervals, current revision/epoch | — | 🔲 **manual / ops follow-up** |
| External untrusted-network probe: raw `9601` / `/diagnostics` unreachable unless an authenticated proxy is in front | — | 🔲 **manual / ops follow-up** |

### Unit/config acceptance (fully runnable locally)

```
go test ./cmd/... ./config/... ./pkg/clientinfo/... \
  -run 'ClientInfoPort|TestReadConfig_ClientInfoPortZero|Initialize_'
```

Proves: no flag/TOML resolves to 9601 by default binding while an explicit
`--clientInfo.port 0` (CLI) and `[clientInfo] Port = 0` (TOML) both resolve to
zero; an explicit 9601 and a custom port enable; and `clientinfo.Initialize`
returns `(nil, false)` for port 0 and a registry for a nonzero port.

### Container matrix (this harness)

| Case | Configuration | Expected result |
|---|---|---|
| compatibility default | omit all client-info settings | TCP 9601 listens internally; `GET /metrics` succeeds |
| explicit compatibility | TOML `Port = 9601` | same |
| CLI compatibility | `--clientInfo.port 9601` | same |
| custom | `--clientInfo.port 9137` | only 9137 responds |
| CLI disabled | `--clientInfo.port 0` | no listener; node still starts |
| TOML disabled | `[clientInfo] Port = 0` | no listener; node still starts |

`clientinfo.Initialize` runs only after `ethereum.Connect`, so the listener
cases require a node that can actually start against a chain (developer network
or a testnet RPC + operator key). Provide those and run:

```
IMAGE=keep-client@sha256:<candidate-image-digest> ETH_RPC=... KEY_FILE=... KEY_PASSWORD=... \
  ./clientinfo-port-smoke.sh listener-matrix
```

The harness's `require_digest` rejects a mutable tag: `IMAGE` (and `PROBE_IMAGE`)
MUST be pinned by an immutable `@sha256:` digest so a smoke run tests exactly the
bytes operators will deploy.

The harness runs each case as a node container on a **private user-defined
bridge network** and probes the client-info port from a sibling `curl` container
— never via a published host port. The network is not made Docker `--internal`
because the node must still reach its Ethereum/Electrum backends to start; the
security property this harness proves is container-to-container reachability with
**no host publication of 9601**. Proving that raw `9601`/`/diagnostics` are
unreachable from a genuinely untrusted external network is a separate manual /
ops follow-up (see the matrix above). `compose.yaml` shows the same
private-network topology for the compatibility-default case.

## Guardrails

- 9601 is a **temporary** compatibility default; the follow-up R2 release flips
  it back to `0` after the monitoring migration. Do not treat this harness as
  permission to publish raw `9601`/`/diagnostics` publicly — always reach it over
  a trusted path (firewall/VPN or an authenticated proxy).
- Do not add an unconditional `-p 9601:9601` to any operator-facing Docker
  sample; the listener stays internal to the container unless explicitly
  disabled with `--clientInfo.port 0`.
