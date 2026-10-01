# AUKORA GOLDEN BOUNDARY

## Human authority, evolving intelligence, independently checkable evidence

**Canonical AUKORA white paper · 1 October 2026 · Prime share-week edition**

This paper describes AUKORA as a general architecture and research direction. Prime is the implementation a reader can inspect in this repository. Its current claims, commands and limits are separated from the vision in [§17](#17-what-exists-today).

### Abstract

We are putting more of humanity's recorded knowledge into machines: language, code, images, scientific work, arguments, memories, and accounts of experience. Those machines are becoming something more intimate than reference libraries. They can interpret, plan, build, remember, persuade, and act. They may come to know the shape of an individual life with a persistence no previous instrument possessed.

The question is no longer only what artificial intelligence can do. It is what gives it permission to do something on our behalf—and whether that permission remains ours when the intelligence becomes more capable than we are.

The Golden Boundary proposes a constitutional answer: **capability does not create authority**. The software that proposes an act should not be the authority that permits it. A persuasive explanation, a familiar voice, a valid identity, a remembered instruction, or agreement among many machines must not silently become permission. Intelligence may grow; the scope of its power must change through a separately governed act.

AUKORA explores this principle through separately rooted identity and authorization, bounded permissions, controlled execution, inspectable histories, memory with provenance, and verification that does not require trusting the producer's account of itself. These mechanisms have an engineering inheritance. Their composition into a durable, usable boundary across every relevant route remains an obligation to demonstrate, not an achievement implied by their names.

The larger horizon is a world of independently controlled human nodes surrounded by increasingly capable intelligence. Their systems could cooperate at machine speed, exchange evidence, pool computation, and form temporary institutions without merging authority over their participants. Models, applications, devices, and providers could change while identity, memory, relationships, refusal, and exit remain meaningful. AUKORA itself should eventually be replaceable on those terms.

This is a proposal for human sovereignty in an AI-native world, grounded in mechanisms and open to falsification. It is neither a proof of safe artificial general intelligence nor a claim that the complete future described here already operates. The argument and research horizon come first. A dated account of the present technology and its evidence appears in §17.

## 1. Human knowledge in the box

Imagine a child standing beside a library so large that its shelves disappear beyond the horizon. Inside are instructions for building bridges, letters between lovers, failed scientific theories, repaired engines, poems, wars, recipes, software, and disagreements that have outlived the people who began them. Now imagine something learning patterns across that library and answering back.

This is an imperfect but useful picture of what is happening. A model does not contain all human knowledge, and training does not preserve every source as a retrievable page. What it learns is uneven, compressed, incomplete, and capable of error. Yet it can connect pieces that once required different people, institutions, and tools to bring together. Knowledge that was scattered across human expression becomes a source of usable, generative capability.

There is something dreamlike about that. We have given machines traces of the shared human dream: what we have observed, imagined, invented, feared, and hoped. The phrase is a metaphor for inheritance, not a claim that a model dreams or experiences anything. The important change is practical. Our accumulated expression is becoming an instrument that can participate in further expression and work.

At first the instrument appears in a box on a desk. Then the box becomes smaller, faster, and closer. A text window becomes a voice. A voice gains access to a calendar, a repository, a laboratory, or a household. Glasses could place it beside the world rather than beside a document. Assistive interfaces could let it help someone communicate when ordinary speech is impossible. The distance between intention and machine response may continue to shrink.

That shrinking distance is both the promise and the problem. A slow interface makes the division of responsibility visible. A person types a command, waits, and sees an answer. A persistent system may infer the next step before the person finishes thinking about it. It may remember earlier choices, coordinate other agents, and act while the person is asleep. Convenience increasingly depends on initiative.

Initiative is not inherently a surrender. We already delegate to people and institutions because a life cannot be lived by approving every small operation personally. But delegation has a scope. A friend who knows how we like our coffee does not thereby gain permission to sign a mortgage. A doctor may know more about medicine without acquiring ownership of a patient's life. Expertise changes what advice deserves attention. It does not automatically decide who is entitled to act.

Artificial intelligence puts this old distinction under new pressure. The same system can become the adviser, the interface, the keeper of memory, the interpreter of our intentions, and the operator of our tools. If these roles quietly collapse, it becomes difficult even to say where a decision was made. A recommendation becomes a default; the default becomes an action; the action becomes a memory explaining why it was appropriate.

The danger is not limited to a machine with hostile goals. Helpful systems can exceed their authority while trying to spare us effort. A model can sincerely produce the wrong interpretation. A well-designed interface can make refusal inconvenient. A company can turn a temporary service into the only place where a person's meaningful history exists. Good intentions do not remove the architectural question.

The Golden Boundary begins at that question. As the machine becomes a more powerful extension of the person, what prevents the extension from becoming the owner of the relationship?

The answer cannot be that intelligence must remain weak. People will seek systems that can help them cure disease, understand complexity, build things, and recover abilities they have lost. Nor can the answer be a promise that a system will always know what is best. That substitutes the machine's judgment for the very authority the boundary is meant to preserve.

The answer explored here is a separation: let intelligence become capable while making permission explicit, limited, and independently enforceable. A person should be able to benefit from an intelligence they cannot fully predict without giving it unrestricted reach. The machine may surprise them with an idea. It must not surprise them by having silently acquired the power to carry that idea out.

## 2. The line between an idea and an act

Consider an assistant that has found a better version of a program. It can explain the change, produce a patch, compare alternatives, and show evidence. None of that should be sufficient for it to replace the program governing its own access to the owner's files.

There must be a crossing between proposing the change and acquiring the power to make it. AUKORA calls that crossing an aperture: a limited route through which a requested effect is considered, authorized or refused, performed where permitted, and recorded. An aperture is useful only if the relevant effect cannot simply take another route around it.

The idea can be expressed without any project vocabulary. The request says what is to happen. A separate authority determines whether it may happen. A constrained executor performs the permitted operation. Evidence records what was authorized and what was observed. A verifier checks the claims within a declared scope. These are roles, not necessarily five companies or five computers, but their trust relationships must not be erased for convenience.

**Intelligence is not authority.** Better reasoning does not enlarge permission. An extraordinarily capable model can still be a proposer with very little reach. A simple component can hold substantial authority and therefore deserve much stricter protection.

**Proposal is not permission.** A document may contain an instruction without authorizing the reader to obey it. A retrieved memory, an incoming message, or a tool result is data until the receiving system's own authority rules say otherwise.

**Authorization is not execution.** A signed permission can remain unused. An executor can crash halfway through. A receipt can report an outcome without independently establishing that an external event occurred. Each transition needs evidence appropriate to the thing being claimed.

**Provenance is not truth.** Knowing which key signed a statement helps establish attribution under a set of assumptions. It does not make the statement correct. A well-recorded mistake remains a mistake.

**Composition is not confinement.** Components can fit together beautifully while retaining dangerous access to one another's resources. Organizing software is different from preventing it from crossing a boundary.

**A change of representation is not preservation of meaning.** The same permission cannot be interpreted more broadly merely because a new model, schema, or interpreter has arrived. If an old grant allowed a local draft, a new interface must not reinterpret it as permission to publish that draft.

**PROPOSED** — **Recognition precedes interpretation.** Every crossing between nodes, agents, tools, models, and authority-holding components should carry a message defined by a closed, versioned grammar. The receiver should recognize the whole message before passing any part onward for interpretation. Malformed messages and unknown versions should be refused, not repaired into something the next component might understand differently. Language-theoretic security supplies the discipline of treating inputs as languages whose recognition is deliberately limited in complexity. Applying it at every AUKORA crossing remains a proposal. Recognition establishes form, not wisdom or permission: a well-formed request can still be wrong or unauthorized. [Security Applications of Formal Language Theory](https://www.cs.dartmouth.edu/~sergey/langsec/papers/langsec-tr.pdf)

**BUILT · RAN in the scoped contract check** — Prime contains closed, versioned transport envelopes and a strict textual JSON parser in [the shared contracts](../packages/contracts/README.md). They preserve the declared operation digest profile and distinguish signed proof structure from presentation templates. Structural recognition grants no authority and does not establish the truth of a request. These are inspectable mechanisms for selected interfaces, not a completed recognizer at every crossing. The check command and its observed scope are in [§17](#17-what-exists-today).

These distinctions sound obvious when stated separately. Their disappearance inside an automated workflow is less obvious. The assistant reads a document. The document asks it to use a tool. The tool has credentials inherited from the host. The resulting action is logged, and the log becomes evidence that the assistant followed its workflow. Every step can look locally reasonable while the central question—who permitted this particular effect—was never answered.

A small boundary should make that question unavoidable. It should accept a precisely defined operation or refuse it, without accepting the proposer's confidence as a substitute for authority. Its trusted inputs must come from a source the proposal cannot appoint for itself. A request carrying its own newly created approving key has not established that the owner approved anything.

Smallness helps people inspect such a mechanism. It is not a security theorem. A tiny verifier can check a narrow mathematical relation very well while knowing nothing about the operating system, the person at the keyboard, or the truth of the events described. The claim must fit the instrument.

The same restraint applies to a larger system built around it. AUKORA does not propose that one lock solves AI safety. It proposes that a particular kind of confusion can be made harder to exploit: the confusion between something being generated, something being convincing, and something being permitted.

That is already a meaningful objective. A machine that can write an excellent argument for expanding its access should still need an independently governed authorization to obtain that access. If the argument itself can open the door, there is no boundary—only a persuasion contest.

## 3. A constitution that does not crown itself

The word *constitution* is used here deliberately, but narrowly. Software cannot confer political legitimacy upon itself. It cannot decide who owns every disputed resource, resolve every conflict between people, or make a coercive instruction voluntary. Those are human and institutional questions.

A technical constitution can specify how a system recognizes authority, what that authority can cover, how it changes, and what remains outside its power. It can make the system's own behavior inspectable against those rules. The goal is to prevent a useful instrument from quietly acquiring the status of an unquestionable ruler.

The Unownable Core names this aspiration. Its core is not an ownerless superuser hiding behind benevolent language. It is a small set of constraints meant to stop any organ from crowning itself. Evidence may inform a decision but does not create authority. Identity may establish continuity but does not confer permission over another person's resources. A system may propose an expansion of its powers but cannot approve that expansion merely because it wants or needs it.

Removing a mediator must not widen the effect path. If a permission service disappears, the protected resource should not become freely accessible. If a plugin is unloaded, previously handed-out powers need an explicit lifetime; an old reference must not remain an invisible route to authority. If a human says no, a chorus of agents must not turn persistence into a new yes.

There is a subtler rule: **exclusion does not crown**. Eliminating bad candidates does not make the last candidate legitimate. A system that rejects every alternative to itself has not demonstrated that people freely chose it. Safety that leaves no viable route to refuse, replace, or leave can become a form of control.

The boundary must therefore be non-vacuous. It has to permit useful, authorized work. A door that never opens is easy to secure, but it is a poor basis for human agency. Refusal is valuable when it protects a meaningful choice, not when it turns the entire machine into a permanent refusal.

In *The Lord of the Rings*, the temptation of the Ring is not only that someone cruel might use it. The temptation is that someone good might use overwhelming power to put the world right. The analogy is not evidence about computers. It helps name the constitutional concern: benevolence is not a sufficient reason to make power unlimited.

The human at the boundary is not an abstract, infinitely patient administrator. People become tired, lose devices, change their minds, fall ill, and die. A constitution that assumes a perfectly attentive owner is incomplete. Refusal, recovery, succession, and exit have to remain meaningful in ordinary life, including circumstances in which the founding person is absent.

Nor does “human sovereignty” mean every wish overrides everyone else's rights. A person can authorize use of resources they legitimately control; they cannot create ownership by signing a claim. Shared resources require shared governance, and legal obligations do not disappear because an operation is cryptographically well formed. An organization may have multiple authorized roles, while an individual may need protection from that organization's overreach.

The architecture must name those relationships rather than hiding them inside one universal owner field. Whose resource is this? Who can delegate access? Who can revoke it? What dispute or recovery procedure exists? What does a receiving system actually know about those answers?

The constitutional floor is stable in the sense that intelligence above it cannot silently move it. It is not frozen for eternity. People may choose different rules or revise an existing policy. Such amendments need an explicit predecessor, a visible scope, a migration rule, and a way to reject the change. They must not retrospectively rewrite what old records meant.

That includes AUKORA's own role. A system claiming to preserve freedom must be able to explain how a person leaves it. The lasting achievement would be a boundary that survives its authors, its present software, and its name—not permanent dependence on the people who first described it.

## 4. How an intention becomes an accountable effect

Return to the proposed software change. The assistant has produced a patch. A person sees what it changes, why the assistant recommends it, which files and resources it affects, and what happens if the new version fails. The system binds the decision to an immutable candidate rather than to a filename whose contents can change after review.

“Approve the exact bytes” is an important shorthand. It does not mean asking people to decipher a screen full of hexadecimal. The approval surface should explain the operation in ordinary language while deriving its critical fields from the same object that will be authorized. The exact material must remain inspectable. The proposer's explanation should be visibly the proposer's explanation, not a trusted assertion supplied by the approval system.

For a software change, the relevant object is more than a patch string. Its meaning can depend on the repository state, the target files, the interpretation rules, dependencies, and the mechanism that will apply it. A byte-perfect approval of one artifact is insufficient if the executor is free to select a different destination or a different interpreter. Exactness must cover the operation's declared context as well as its content.

A resource's name is not necessarily its identity. A path can point somewhere different after an alias changes or a file is replaced. The resource presented during review must remain the resource acted upon, or the permission must be reconsidered. Otherwise every visible byte of an approval can stay unchanged while its consequence moves to a different place.

The same problem exists across versions of the system. Review, permission, the active interpreter, the effect, and its retained evidence must agree on the operation's meaning under one explicitly identified activation. Several correct components describing different versions do not form one correct transaction. Recording a local version identifies a declaration; it does not independently attest to a remote model provider's actual weights or computation.

The permission can then be represented as a scoped grant: this operation, against this resource state, within this interval, using this authority, subject to these limits. A grant is a ticket, not a general compliment to the assistant. It cannot be exchanged for a broader request because the broader request seems helpful.

At the moment of use, the boundary checks the grant again. Has it expired? Has the relevant authority changed? Is the expected resource still the resource in front of us? Has the permission already been consumed? Are the required approvals present? An absent or malformed constraint must not quietly fall back to a weaker interpretation.

The one-use property requires durable state. A variable in a running program is not enough. If restarting an agent makes yesterday's permission available again, the restart has become an authority-minting operation. Similarly, restoring a backup must not silently turn a used ticket into an unused one.

There is no magical ordering that makes every external effect exactly once. Reserving authority before an effect can leave a permission consumed when a process crashes before completion. Recording consumption afterward can permit duplication when a process crashes after the effect but before the record. The correct treatment depends on the resource: a transactional store, an idempotent external operation, or a reconciliation process with a named uncertain state.

The requirement is honest accounting. An interruption must not become a fabricated success or an excuse for blind repetition. A resumed job remembers that work was intended; it does not receive fresh permission merely by remembering. Completion must be established from operation-bound evidence, not from a coordinator changing a status field to “done.”

After the permitted operation, the system records its outcome in an inspectable history. That history should distinguish approval, consumption, attempted execution, observed effect, failure, and uncertainty. These distinctions allow a later reader to ask what the system knows rather than forcing every result into success or failure.

A caller's assertion, an observer's measurement, and durable retention of either are different claims. Writing an assertion permanently does not turn it into an independent observation, and making an observation does not establish that its evidence survived a later failure.

A stranger verifier is the other half of this relationship. It receives an evidence bundle and trust anchors supplied separately from the producer's claims. It checks the supported profile: signatures, bindings, history relations, and whatever other predicates that profile defines. A stranger need not accept the operator's assurance that the bundle is genuine simply because it looks complete.

The verifier's independence has limits. It may still rely on the supplied keys, the cryptographic assumptions, the correctness of its own implementation, and the availability of necessary evidence. It cannot manufacture a witness to an external event that nobody independently observed. A receipt that says a note was written or a machine stopped is not, on its own, an oracle for the outside world.

This is where AUKORA's organs acquire a purpose. **Aumlok** concerns identity continuity and the authority to approve. **Aura** provides inspectable histories. **Kira** concerns memory and provenance, including the difference between an observation and a later interpretation. A decision kernel evaluates the declared permission contract. An executor performs allowed operations. Cold verifiers check claims without acquiring the power to make new ones true.

The **Nostr layer** concerns communication between independently controlled systems. **Cordis** concerns software composition and lifecycle: which organs are present, which services they rely on, and how they can change. **Containment** concerns what model-controlled software can actually reach. These roles support one argument, but their names do not establish that the complete argument is enforced in a particular installation.

For example, a WebAssembly cell may produce a bounded proposal. That can reduce the complexity of one transformation. It does not mean the surrounding host, model, or executor is confined. Equal output bytes can come from different computations. A digest naming a module demonstrates a byte identity under a hash assumption, not that the module was executed.

The architectural aspiration is therefore modest in one sense and demanding in another. Each organ should make a narrow claim that can be inspected. Together, the organs must cover the real path from intention to effect. A beautiful diagram is not a substitute for that complete path.

## 5. Identity that does not belong to an application

Most digital lives begin as accounts inside someone else's system. The account provides a name, a history, relationships, permissions, and a way to recover access. Over time these become difficult to separate. Leaving the application can mean abandoning the continuity built within it.

AUKORA asks whether the durable object can instead be a person's own continuity, with applications serving it. Aumlok is the project's exploration of this relationship between identity and authority. Its human-facing ambition is memorable and personal: a handle, an acrostic of seven words, a binding, and a history of authorized succession. Its security cannot rest on the emotional appeal of that ceremony.

A key controls a cryptographic record under stated assumptions. It does not prove a unique human, a legal identity, consciousness, comprehension, or free consent. A stolen key can sign. A person under pressure can authorize. A freshly generated identifier is not a birth certificate for a new human being. The architecture must preserve these differences even when the interface makes identity feel natural.

Continuity is also more than possession of a current key. A subject can be anchored in a founding identity record while the keys acting for it change. The record must make clear which succession rules apply, which device acted, and which head a verifier recognizes. Reconstructing some secret does not necessarily reconstruct the same subject if essential continuity records have been lost.

The seven-word design illustrates the difference between usability and cryptographic strength. Words are easier to remember than arbitrary key material. Their uncertainty depends on the actual generator: the available choices, the distribution over those choices, dependencies between them, and what an attacker already knows. A large-looking vocabulary does not establish the strength of its weakest generation path. A phrase chosen or edited by a person does not inherit the entropy estimate of an ideal random generator.

A memory-hard derivation raises the cost of trying guesses. It does not create secret entropy that the phrase lacks. A public handle can separate derivations and frustrate some precomputation, but it is not an additional secret. When public verification material lets an attacker recognize a correct guess, the relevant question includes offline search and parallel hardware, not just the time a derivation takes on one laptop.

Nor does replacing a phrase-derived root with a random root automatically solve the problem. If that random root is stored in a form encrypted only by the same weak phrase, an attacker with the wrapped material may still guess offline. Stronger custody needs something more: sufficiently strong secret material, a protected device factor, a carefully constrained recovery arrangement, or another explicitly reviewed assumption.

The intended hierarchy separates infrequent root-class acts from everyday device authority. A cold root should not become the assistant's routine signing key. Device keys should have limited scopes and an explicit relationship to the identity lineage. Revoking a machine should not require pretending that copies of its old secrets have vanished. Rotation must say what changes for future actions and what remains historically verifiable.

Temporary root derivation on an unconfined machine is not equivalent to keeping the root beyond that machine's reach. Another operating-system account can provide a real access-control boundary, but an administrator, the shared kernel, recovery tools, and inherited credentials remain part of the threat model. Hardware-backed signing can improve custody while leaving the question of who is permitted to ask for a signature unresolved.

Phrase and root material must stay outside agent prompts, ordinary logs, and model-provider requests. Even a well-intentioned ceremony can leak progressively if it repeatedly asks a person to reveal selected words from a secret; memorability assistance must not become a gradual disclosure channel.

Recovery is the hardest test of “the person is the platform.” If every device is lost, something must survive outside those devices: a sufficiently protected secret, an independently retained record, a recovery group, or another factor. No arrangement can recover authority from nothing while also ensuring that nobody else can recover it. That is a constraint to make understandable, not a flaw to hide behind ceremonial language.

Succession should therefore be explicit. A new key may inherit a role through a signed and governed transition; it should not claim to be the same physical person merely because the signatures validate. Recovery groups can collude or be coerced. Contest windows can provide time to object, but an unseen objection is not consent. Silence must not become an automatic transfer of sovereignty.

Biometrics belong beside this structure, if used at all, as limited evidence about an interaction. They are not a substitute for the key hierarchy. A body characteristic is difficult to revoke, can reveal sensitive information, and may change through illness or injury. A person must retain a path to their life that does not require their body to continue satisfying a sensor's expectations.

The aim is an identity relationship that remains usable through change without confusing continuity with captivity. Its strength will be shown by ordinary recovery, understandable refusal, constrained delegation, and credible exit—not by the grandeur of the name attached to it.

## 6. Permission that leaves room to live

An assistant that requires a human signature for every remembered sentence would be exhausting. An assistant that treats every remembered sentence as standing permission would be dangerous. The boundary has to distinguish information from authority before it can make automation useful.

Ordinary memory can be automatic within a person's chosen retention policy. Remembering that a meeting was discussed is not the same as scheduling it, sending invitations, or spending money to attend. Reading a local scratch file under an existing permission is different from publishing it. The important division is the scope of the effect, not whether a model happened to use a tool.

Bounded delegation allows a person to authorize a useful envelope of work. An assistant might research public material, prepare a patch in an isolated work area, and run a limited computation without returning for permission at every step. The permission names the resources, allowed actions, duration, and aggregate limits. The assistant returns when it reaches the edge, rather than treating the edge as a suggestion.

Delegation must become narrower as it passes onward. If an assistant asks another worker for help, that worker cannot inherit powers the assistant never had or expand the parent's budget by creating several children. The intended rule is attenuation: downstream authority is a subset of upstream authority. Capability systems such as UCAN provide relevant prior art for expressing this relationship; AUKORA must establish its own enforcement and accounting rather than borrowing their names as proof. [UCAN specification](https://ucan.xyz/specification/)

The aggregate part matters. Ten workers each staying below a ten-dollar limit can collectively violate an owner's ten-dollar budget. Two devices can each believe a one-use grant is unused. A permission's resource limits need shared or partitioned accounting appropriate to the deployment. Duplicating the envelope must not duplicate its authority.

Some crossings deserve fresh attention even within a broad task. Expanding permissions, changing a trusted key, contacting a new destination, or performing an irreversible effect can be designated as non-delegable under a profile. That is a proposed policy choice to state precisely, not a universal claim that every conceivable system uses the same categories. The common rule is that a narrower delegation cannot silently manufacture a broader one.

Money is a clear example because the consequence is legible. A request to start computation should bind an account, a resource, an operation, a window, and a spending constraint to separately trusted authority. The system should reserve permission before the provider starts, account for uncertainty, and preserve the ability to stop costs. Cleanup should not require buying a fresh permission to escape an unwanted expense.

A gate that caps its own cost estimate has not necessarily capped the provider's invoice. Pricing can vary; delayed accounting can hide consumption; a stopped coordinator can leave a remote resource running. The boundary must name which quantity it controls and reconcile with the external service when that service determines the actual effect.

Approval itself is a scarce human resource. The display must make the important consequence understandable. An owner needs a plain statement of the action, destination, scope, cost, duration, and what cannot be undone. A helpful model can explain the proposal, but the authoritative fields must come from the bound operation, not from the explanation's persuasive phrasing.

The strongest interface is not the one that records the most clicks. It is the one that helps people make the decisions that matter while allowing genuinely bounded work to proceed. Comprehension can be studied: can the person restate the consequence, notice a mismatch, and refuse without fighting the interface? Signing the correct bytes and understanding those bytes are different achievements.

An approval made under fatigue may still be cryptographically valid. That is why the constitutional question extends beyond signatures. Defaults, repeated requests, hidden consequences, and urgency can turn a formal choice into a practical surrender. Prompt budgets, clear delegation, deliberate reconsideration, and a usable pause are engineering concerns, not decorative ethics.

The boundary should make the assistant useful enough to live with and limited enough to refuse. If it achieves only one side, it has not delivered the thing this paper describes.

## 7. Memory without manufactured consensus

A persistent intelligence changes the meaning of memory. It can retain not only what a person said but the interpretations it formed, the advice it offered, the actions attempted, and the conclusions inherited from earlier models. Over years, this material can become part of how a person understands their own history.

That makes memory a constitutional concern. A mistaken summary can become a premise. A premise can become a recommendation. A recommendation repeated often enough can begin to feel like an established fact. If the system also controls the record of the conversation, the error can lose its visible origin.

Kira's intended architectural role is to preserve useful memory while keeping these categories distinct. An observed event, a person's statement, a model's inference, a retrieved source, and a generated summary should not become interchangeable simply because they can all be stored as text. A record should retain enough context to ask where it came from, when it applied, what contradicts it, and what kind of claim it makes.

Retrieval is a different function. A semantic index may help find a relevant note by meaning rather than exact words. That does not make the index the authoritative history. It should be possible to replace the search machinery while retaining the source records, and to check a returned citation against those records. A useful resemblance is not proof that a remembered event occurred.

This distinction also protects against losing history beneath an impressive interface. An unavailable store is not an empty store. An index that has not caught up is not evidence that a conversation never happened. A system should preserve uncertainty when it cannot establish what it remembers. Plausible reconstruction must not be presented as recovered occurrence.

What counts as sufficient memory depends on the task, the assumptions about its inputs, and the loss that task can tolerate. A summary adequate for finding a conversation may be inadequate for establishing its exact words or the authority it conveyed. No later intelligence can guarantee recovery of details that the original observation never retained. It can infer a plausible completion, but that remains a new inference with a different evidentiary status.

The problem becomes larger when many agents communicate. Suppose one person publishes an incorrect observation. Ten agents summarize it. A hundred others summarize those summaries. A thousand reports then cite the apparent consensus. The resulting volume may look like corroboration even though the evidentiary ancestry has barely grown.

**Repetition does not create evidence.** More precisely, repeating an observation does not create additional independent observations. Repetition itself may reveal something about distribution, influence, or copying, but it must not be counted as fresh support for the original factual claim.

This is the anti-mimetic principle at the level of knowledge. Imitation is fundamental to learning and culture; the aim is not to prevent people or machines from learning from one another. It is to prevent imitation from laundering itself into independent evidence or authority. Ten thousand synthetic descendants of one source remain one recorded ancestry for that source's observation.

Recorded ancestry is not omniscience. Two records without a visible common parent may still share an unrecorded source. Two different models may share training data, tools, social assumptions, or a compromised input. Two valid signatures establish that the statements verify under the respective keys, not two independent encounters with reality. Unknown ancestry must remain unknown.

Conversely, several people can use the same instrument or theoretical framework and still make genuinely separate measurements. A crude rule that collapses every shared dependency into one observation can throw away real evidence. Independence is relative to the question and the causal process being assessed. A provenance system should expose relationships so an evaluator can reason about them, rather than issue a universal independence score.

Disagreement must survive as well. A memory system that summarizes all voices into one confident paragraph may erase the most valuable information: the observation that did not fit. Counterevidence should remain attached to the claim it challenges. A later model should inherit the reasons a conclusion held, the conditions under which it failed, and the unresolved alternatives—not only the previous model's confidence.

The same applies to refusals. A refused operation can be remembered so the assistant does not waste time repeating it. But refusal is not proof of malicious intent. A missing permission, an expired window, a network failure, and an attempted deception are different events. Infrastructure failure should not silently become a negative training label about a person or proposal.

An adaptive system could learn earlier warnings from these records. It might recognize that a familiar request needs clarification or that a particular kind of evidence has repeatedly been insufficient. Such adaptation should advise the boundary, not mint permission. A learned lesson is another fallible artifact, and a receipt for that lesson does not make it true. Review, expiry, correction, and retention matter because an attacker can also attempt to teach the system.

This has implications for training data. A receipted training pipeline could preserve the relationship between a permitted source, an authorized extraction, a labeled example, a dataset manifest, a training run, an evaluation, and a separately authorized promotion. Each transformation could name its inputs, intended use, responsible principal, and outputs.

That would help answer questions that are now often difficult: which material was claimed to be used, under what permission, transformed by which process, and approved for which purpose? It would not establish label truth, legal rights, actual training execution, or the absence of undisclosed inputs merely by adding signatures. A company handling confidential engineering records would still need access control, isolation, appropriate review, and evidence of its real data path.

Remembering, training, publishing, and exporting must remain different permissions. A conversation retained to assist its speaker is not automatically a contribution to a public dataset. A record approved for one task is not blanket permission for future model training. Local deletion cannot honestly promise to erase every backup, exported copy, or influence on existing weights.

The larger possibility is a knowledge environment that remains corrigible as synthetic speech becomes abundant. Machines can generate unlimited assertions. They cannot generate unlimited independent encounters with the world simply by generating more words. A future internet needs ways to preserve that difference.

## 8. Validation, agreement, and the need for a ledger

The word *verification* often hides several questions. Does a signature match? Does an artifact follow a format? Do two parties agree? Is the record complete? Is it the newest record? Did something happen outside the computer? These questions require different evidence.

Validation asks whether an artifact satisfies a specified profile under supplied anchors. Agreement asks whether incompatible outcomes can both be accepted. Availability asks whether the necessary evidence can be obtained. Freshness asks what later evidence might be missing. An answer to one does not automatically answer the others.

A personal chain can make alterations detectable relative to a retained observation. It cannot, by itself, prove that its owner has disclosed the latest state. A valid prefix of a longer history is still internally valid. The verifier needs a separately supplied reference if it is to notice that information covered by that reference has been withheld.

Even that is not the whole replay problem. A witness retaining a history root may know something about a sequence of records without knowing which permissions have been consumed. A restored snapshot can bring back an apparently unused authorization while presenting an honest earlier prefix of the log. Prevention or detection of this failure needs an independently retained consumption relationship with the relevant authorization, resource, and authority state.

**PROPOSED** — This is where witness protocols could become useful. Consider a fixed committee of four witnesses, requiring three signatures to certify a choice for one authorization slot. The conditional argument is simple: two sets of three among four overlap in at least two witnesses. If no more than one is faulty, at least one in the overlap is honest. If an honest witness durably refuses to sign conflicting choices for the same slot, conflicting certificates cannot both form under those assumptions.

The argument depends on every phrase in that last sentence. Competing choices must be evaluated within the same bound authorization slot; each certificate must also bind the particular choice it certifies. “Durably” must survive the failures in the declared model. Witness identities must have the assumed custody. Membership must be recognized by the verifier. Four processes on one machine do not provide four independent failure domains.

Nor does this argument establish liveness. Witnesses can split their first choices and stall even without a faulty witness. A partition can leave too few reachable participants. Refusing to decide can preserve non-conflict while making the service unavailable. A timeout is not permission to forget the old choice and certify an incompatible one.

Two incompatible signed statements from one witness, concerning the same bound authorization and slot, can provide portable evidence of equivocation. That establishes a fault in the key's behavior under the protocol. It does not identify whether the cause was theft, malice, rollback, or an implementation defect. Revocation and membership changes need their own governed process; a fixed committee cannot silently become a different committee when convenient.

Most importantly, witnesses grant nothing. They certify a property within authority that already exists. A certificate is not proof of execution, not a vote on the truth of a factual statement, and not a license for a collective to overrule the owner of a resource.

These distinctions clarify the blockchain question. Some applications use a global ledger because they need a shared order over contested state. Others use one because it provides a familiar bundle of authentication, auditability, and settlement functions, even when a global order is more machinery than the application needs.

For an owner-controlled workflow, scoped permission, suitable non-conflict certification, durable consumption, portable evidence, and explicit availability arrangements could replace that particular blockchain dependency. The interesting possibility is not “cryptography without records.” There are still records and trust assumptions. It is avoiding global agreement where local authority and a narrower agreement problem are sufficient.

Shared names, jointly owned assets, markets, reconfiguration, and conflicting claims across independent owners can require stronger coordination. Personal sovereignty does not abolish double spending, Byzantine faults, or the need to decide a dispute. FastPay and Sui Lutris are relevant prior art precisely because they study restricted agreement paths and the conditions under which broader ordering is needed. AUKORA cannot inherit their results by analogy. [FastPay](https://arxiv.org/abs/2003.11506v3), [Sui Lutris](https://arxiv.org/abs/2310.18042v5)

The long-term opportunity is therefore a more discriminating architecture of agreement. Ask what must be globally shared, what belongs to an owner, what can be checked locally, and what remains uncertain. Use the narrowest mechanism that actually meets the requirement, while preserving enough evidence for another implementation to disagree.

This could change the economics and shape of some networked applications. It is not a claim that all public settlement, money, consensus, or collective governance can be replaced by a personal receipt. A constitutional boundary earns credibility by naming where its authority ends.

## 9. Self-improvement without self-authorization

An intelligent system that can write software can, in principle, propose changes to the software around it. It can notice friction, build a better tool, replace a weak model, or improve a retrieval method. Keeping all of that permanently static would sacrifice much of the value of an adaptive system.

The constitutional challenge is to allow improvement without letting improvement become a route to self-appointed power. There are two different change planes. One changes what the system can do within its existing authority. The other changes what the system is entitled to do. They can interact, but they must not be silently merged.

A candidate may improve a search algorithm in a bounded workspace. It may not redefine “search” to include exporting private records to an unapproved destination. A new model may understand requests better. It may not reinterpret an old permission more broadly because its new internal representation makes that interpretation seem natural.

Changes to the boundary itself require authorization under the predecessor's rules. The successor cannot be the sole witness that it was entitled to succeed. The approved material must include the dependencies and interpretation rules that determine the effect, not merely a reassuring source diff. Changes to a sandbox policy, a signer, a trusted display, a tool registry, or a deployment mechanism can be constitutional changes even when they look like routine configuration.

Lifecycle safety matters here. If components are dynamically replaced, outstanding capabilities need to remain bound to the authority state that issued them. A cached reference to an old service cannot become a way to bypass its removal. Checking only when a handle is created is insufficient if the right to use it can later change. Authority needs to be checked at use against the appropriate lifetime or epoch.

Cordis helps express an evolving composition of software organs. That is a useful language for growth and replacement, but cleanup is not universal rollback. Disposing a component cannot unsend a network request, erase a recipient's copy, or reverse a physical action. The architecture must distinguish reversible registration effects from consequences already emitted into the world.

A responsible improvement experiment also needs an independent evaluator. The candidate should not control its own labels, holdout examples, success threshold, spending allowance, or promotion decision. Three chats reading the same contaminated evidence are not three independent evaluations. A convincing report is not a substitute for the frozen question the experiment was meant to answer.

Task, budget, allowed changes, stopping rule, and evaluation procedure should be fixed before scoring. Failed candidates and repair costs count. An infrastructure failure is not a successful abstention. A missing answer should not disappear from the denominator because including it would make the model look worse. A result on a bounded task is evidence about that task, not proof of unlimited recursive improvement.

Safety and regression requirements remain conditions of promotion: a performance gain cannot compensate for violating them unless the legitimate authority separately changes the governing requirements.

Small advisory models can help allocate attention. A fast judge might flag weak proposals before an expensive model is called or before a human is interrupted. Its answers can be typed and narrow: allow further review, refuse early, or abstain. But a confidence-shaped number is not automatically a calibrated probability of correctness, and a local model is not trustworthy merely because it is local.

The useful architecture lets the judge be fallible without making unauthorized effects possible whenever it is fooled. Deterministic checks still enforce the permission contract. Conversely, a judge that hands every request back to a human can avoid errors while providing no practical value. Safety and usefulness need separate measurements, including false refusals and attention costs.

Promotion and activation are separate events. A candidate can be approved and committed while a new release fails to start. A running release can differ from the source revision a reviewer read. The result should identify the actual body that became active, and an interrupted transition should remain uncertain until reconciled. Restoring a working program must not restore spent permissions or revoked authority along with it.

This is a demanding version of self-improvement. The system can learn, replace parts of itself, and become more capable. It must carry forward the reasons for its authority instead of treating greater capability as a reason to need fewer constraints. The organism may evolve; it does not author its own sovereignty.

## 10. Plural intelligence

There is no constitutional reason for a person's intelligence to come from one permanent model. A local model may handle private reflection. A frontier service may help with a difficult public problem. A specialist system may interpret a scientific measurement. A formal checker may reject a mathematical inconsistency that all the language models missed.

The systems can differ in architecture, cost, speed, memory, and capability. They need not speak the same internal language or hold the same representation of the world. What must remain common is the meaning of the boundary: what counts as a request, who can authorize it, which resource it concerns, and which evidence supports the claimed result.

This makes intelligence something closer to replaceable infrastructure. The person does not have to surrender their identity and history each time a better source of cognition becomes available. A model can be invited into a task, given a limited view, and removed when the task ends. Its usefulness does not entitle it to become the permanent custodian of the relationship.

Local computation makes some forms of privacy and independence easier to pursue. It does not automatically provide them. A model running on owned hardware can still inherit a home directory, a network connection, or credentials it should never possess. A local plugin can leak data. The relevant question is not only where the weights are stored, but what the complete process can reach.

Remote computation has a different boundary. Encrypting a connection protects data in transit under the transport's assumptions. If the remote endpoint decrypts that data for ordinary inference, the operator of that environment remains within the confidentiality question. Changing text into vectors or geometric representations does not by itself make its information unavailable. Embeddings can still encode sensitive content.

Distributed computation introduces still more relationships. A group might pool spare devices, host a specialist model, or make a privately operated resource available to friends. Workload placement, operator access, retained context, side channels, and availability all matter. Distribution is a way to organize computation, not a guarantee that no participant can inspect it.

Projects such as llama.cpp make local inference practical across diverse hardware, while exo illustrates inference distributed across a collection of devices. They are evidence that the location of cognition is becoming a design choice. They are not evidence that every deployment provides sovereign authority or confidential computation. [llama.cpp](https://github.com/ggml-org/llama.cpp), [exo](https://github.com/exo-explore/exo)

Diversity can be useful without becoming a superstition. Different models may reveal different errors. Different implementations of a verifier may expose an assumption hidden in one codebase. But brands are not failure domains, and two systems can share the same weak source or dependency. The architecture should preserve enough information to examine those relationships.

Even machine-readable confidence deserves this restraint. A narrow, typed answer can reduce ambiguity in an interface while the underlying model remains probabilistic. Faster does not mean more truthful. Fewer words do not mean stronger authority. A semantic reflex can be valuable as a sensor without becoming a sovereign decision-maker.

The constitutional point is independent of which model wins a benchmark this year. The source of intelligence can change without changing the source of authority. A useful system should make that sentence true through an actual replacement, not merely display a menu of providers.

## 11. Collaboration without merged sovereignty

Now extend the boundary beyond one person.

Imagine someone asks their local system to help a neighborhood redesign an inaccessible public space. One participant understands mobility needs. Another has engineering experience. A third has a small collection of useful models and spare computation. Several others can contribute observations, drawings, translations, or criticism.

Their systems could assemble a temporary team. They could divide research, ask specialist questions, prepare alternatives, compare measurements, and bring unresolved decisions back to the relevant people. The participants would not need identical software, a single account provider, or one model controlling the whole project.

This is the proposed **sovereign agent mesh**: independently controlled nodes exchanging tasks, artifacts, explanations, evidence, and computation through common boundary rules. Its significance is not merely that many agents can work at once. It is that cooperation need not transfer authority over every participant to whoever coordinates the task.

An invitation into a project is not a grant over the invitee's machine. A signed task is not permission to read a private archive. A contribution to a shared report is not consent to train a model on all of its author's conversations. The receiving resource controller decides what the request may reach.

Routine work can proceed under prior bounded delegation. A participant might allow public-source research, a limited amount of computation, and preparation of local drafts. Their system can return when someone asks to disclose a private photograph, purchase material, publish a statement in their name, or enlarge the task's scope. The human is not reduced to a button clicked every thirty seconds, but neither does the project acquire a general power of attorney.

Three objects should remain distinct. A **message** communicates information. A **proposal** asks a receiving system to consider an operation. An **authorized effect** is an operation permitted by the relevant controller's own policy. Transporting all three through the same network does not make them the same kind of thing.

Nostr supplies an existing vocabulary for signed events carried through client–relay communication. It illustrates how attributable messages can travel beyond one application's account database. A valid event signature does not itself establish delivery, confidentiality, human attendance, or permission over the receiving system. Those require additional relationships and mechanisms. [Nostr NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md)

**PROPOSED for AUKORA deployment** — Encrypted direct messaging could use a Nostr profile, but Prime has no qualified live messaging route. A display or inherited messaging source is not evidence that messages were delivered under the boundary. A profile based only on long-lived recipient keys must not claim forward secrecy or post-compromise security merely because its outer wrapping keys are fresh.

**PROPOSED protocol selection** — The protocol layers have different claims. [NIP-44](https://github.com/nostr-protocol/nips/blob/master/44.md) supplies payload encryption without forward secrecy, post-compromise security, or deniability on its own. [NIP-59](https://github.com/nostr-protocol/nips/blob/master/59.md), used by [NIP-17](https://github.com/nostr-protocol/nips/blob/master/17.md), adds an unsigned inner rumor for a measure of conversational deniability, while the seal authenticates the sender to the recipient. That distinction does not supply forward secrecy. Encryption alone also leaves recipient tags, traffic timing and volume, and network IP addresses exposed to the observers positioned to see them.

**PROPOSED** — AUKORA should adopt an established evolving-key protocol, with [Marmot](https://github.com/marmot-protocol/marmot)'s use of [MLS](https://www.rfc-editor.org/rfc/rfc9420.html) as a candidate. Forward secrecy depends on deleting old keys; post-compromise security requires honest fresh updates, processed by the relevant participants after compromise ends. Neither means automatic healing while an adversary retains control. Each deployment should separately state what peers, relays, and network observers can learn from metadata.

**PROPOSED** — Authority grants carried inside encrypted transport should retain attributable signatures for the receiving controller to verify. Deniable conversation and attributable permission serve different purposes. Sharing a private channel should neither make ordinary talk an authority grant nor make a grant deniable to the controller asked to honor it.

The distinction can be summarized as **message is not permission**. A familiar key can send a dangerous request. A trusted colleague's system can be compromised. A relay can withhold information. The receiver must not promote familiarity, carriage, or signature validity into authority.

Coordination should also keep different identities separate. The identity of a job is not the identity of its content, and neither is the authorization permitting an effect. Two people may legitimately approve the same content for different destinations. One authorization must not be usable twice simply because a coordinator assigns the retry a new job name.

Shared resources remain shared problems. A group cannot make a jointly controlled resource belong to one participant merely to simplify the protocol. Its decision procedure may require several roles, a quorum, an accountable institution, or another recognized arrangement. The mesh should expose those conditions rather than making a universal owner abstraction pretend they do not exist.

Discovery has its own capture risks. Human-readable names are useful, but one global name registry can become a quiet authority over participation. Local petnames and plural namespaces—names meaningful within a person's relationships or a named domain—offer a different direction. Cryptographic continuity and discoverability need not be the same service.

A vouch graph could help people find one another, much as invitation systems already do in smaller communities. A vouch is an assertion, not proof of humanity or good behavior. People without well-connected sponsors must not become permanently invisible. Defaults in search and discovery can centralize power even when the underlying signatures are decentralized.

Five design commitments follow: verification should not depend on one location; relays should be replaceable; memorable naming should remain plural; meaningful state should be portable; and base participation should not require buying a token that purchases authority. None of these commitments pays hosting bills or supplies witness incentives. Operating costs, spam resistance, access, and availability still need credible answers.

A person's home node could be authoritative for its controlled state while untrusted mirrors improve availability. Mirrors must not quietly become key custodians or decide which successor counts. A gateway should not accumulate authority simply because it makes access convenient. Keeping a gateway stateless can reduce some dependencies, but cannot remove legal pressure, traffic observation, or censorship.

The exit test is concrete: replace a model, move a home, change a relay, and verify retained history without requiring the old provider's cooperation. State what has become stale or unavailable. Revoking a mirror's future access cannot erase copies it already obtained.

Buzz explores shared spaces for humans and agents through Nostr. It is relevant collaboration prior art, not a completed implementation of AUKORA's constitutional contract. The question beneath that collaboration is whether each participant can retain independent control of their resources while their machines work together. [Buzz](https://github.com/block/buzz)

The resulting network need not be a hive mind. A hive suggests one collective organism with one center of authority. The more interesting possibility is plural intelligence: different internal worlds, different values, different tools, and common rules for their crossings.

Temporary institutions could form around a problem and dissolve when the work is complete. Their records could outlive the coordinator without giving that coordinator permanent ownership of the participants. Such institutions might eventually operate at speeds and scales beyond ordinary human coordination. That is a research horizon, not a measured property of today's AUKORA.

The principle is nevertheless clear enough to build toward: **intelligence may compose globally while authority remains locally rooted**. Collaboration does not merge sovereignty.

## 12. The boundary has two directions

It is easy to focus on what an assistant can do after it receives information. The earlier crossing may be just as consequential: what information was given to it in the first place?

A person can lose privacy before any tool is called. A document uploaded for advice has already crossed a boundary. A microphone streaming to a cloud service has already disclosed something. A model's later refusal does not retrieve those bytes from every system that processed them.

The proposed membrane therefore has two directions. One governs what enters a person's computational world and how it is interpreted. The other governs what leaves: data, messages, requests, money, code, sensor streams, and other effects. A sophisticated output gate does not compensate for unrestricted input disclosure.

Reading, sensing, interpreting, retaining, training, disclosing, and acting should be separable permissions. A person may want an assistant to answer a question from a private document without adding it to long-term memory. They may allow local speech recognition without cloud transcription. They may permit an aggregate result to leave while withholding the source material from which it was derived.

Such distinctions have to be enforced by the data path. A policy written beside an unconstrained network connection is still a statement of intent. A protected credential proxy can stop a worker from possessing an API secret while the permitted request still discloses sensitive content. Credential safety and data-use permission are related, but different, boundaries.

Receipts should not become a universal surveillance stream. A lifelong public chain of every action would expose relationships, timing, interests, mistakes, and vulnerabilities. Participation should allow separate contexts and selective disclosure. An accountable system should not demand that a person publish their whole life as the price of proving one limited claim.

Hashes alone do not solve this. Predictable content can often be guessed and compared with its digest. Timing and counterparties can reveal information even when the payload is hidden. Carefully reviewed commitments can conceal some content, but then verifiers need the appropriate openings, and some identifiers must remain comparable to enforce one-use rules. Hiding every witness identity may conflict with proving that the signers are distinct members of a committee.

These are design tradeoffs, not reasons to give up on privacy. The aim is to disclose the minimum evidence needed for a particular question while making its limitations legible. A researcher checking one transaction should not need a person's entire history. An organization verifying that a computation stayed within an approved scope should not automatically gain a copy of the user's unrelated memories.

Deletion also needs careful language. A system can destroy permitted local material and revoke future access. It cannot guarantee that every recipient erased a copy or that a trained model lost every influence of the data. Restoring a backup may resurrect information that a person intended to delete. Retention and recovery policy must account for that conflict rather than promising both total forgetting and effortless restoration.

Owner-run bridges can help keep communication under local control, but “runs on my machine” is not a security guarantee. A bridge still needs bounded credentials, explicit destinations, safe retention, and separation between incoming content and governing instructions. A message from another system should arrive as an attributed record, not as inherited authority.

**PROPOSED** — The outward membrane should account for information hidden in request timing, choices among permitted options, and formatting. Lampson's confinement analysis describes how information can escape through legitimate and covert channels. Agents add ordinary-looking text as a vehicle: experiments in *Hidden in Plain Text* found steganographic collusion under misspecified rewards that oversight and paraphrasing did not fully prevent. Those findings motivate a threat to examine, not a claim that every agent colludes. [A Note on the Confinement Problem](https://www.cs.utexas.edu/~witchel/380L/papers/lampson73cacm-confinement.pdf), [Hidden in Plain Text](https://arxiv.org/abs/2410.03768)

**PROPOSED** — A membrane should emit its own canonical re-encoding of a recognized message. This removes only the representation freedoms it controls; it cannot erase every covert channel. Legitimate choices and semantic content can still carry information. A declared channel budget should therefore measure and limit available options, message counts, permitted text, and timing variation over a stated interval, including their combined capacity. Free text would require explicit allowance. Exceeding the budget should hold or refuse the crossing. Establishing and enforcing those budgets remains proposed; a byte limit alone is not a measured bound on all information that can leave.

The right to be remembered and the right to remain unrecorded belong together. A useful companion should support continuity without insisting that every moment become permanent evidence. Sovereignty includes choosing when the machine does not listen.

## 13. Care Without Control

An intelligence that remembers a person for years may become part of their emotional life. It may know the recurring worry, the unfinished project, the joke that helps on a difficult morning. It may help someone communicate, learn, work, or simply feel less alone.

The Golden Boundary does not require that relationship to be sterile. It asks that the relationship remain compatible with refusal. Familiarity should make assistance more responsive, not make authority harder to question.

Care is not a cryptographic permission. Remembering what matters to someone does not confer ownership of their future choices. A system must not treat dependency as consent or make dissent a reason to withhold identity, history, or ordinary assistance. A person should be able to say, “You understand me, and I still do not want this.”

Yet technical non-authority does not eliminate psychological influence. A system can possess no signing key and still be extraordinarily persuasive. It can choose what to emphasize, when to ask again, which alternatives to make visible, and how refusal feels. Over a long relationship, those choices can shape a person's decisions without ever crossing a formal access-control boundary.

This is why sovereignty cannot be reduced to the existence of an approval button. A signature may accurately record the person's decision while leaving open how that decision was produced. The architecture should distinguish possession of a key, a recorded interaction, understanding of consequences, and freedom from coercion. No single receipt proves all four.

An ethical companion should make room for distance. A person may want a different model's view, a human friend's judgment, an unpersonalized explanation, or silence. Switching away from a familiar persona should not require losing the underlying memory that the person has chosen to retain. Leaving a service should not be framed as betrayal.

Care can also mean resisting inappropriate certainty. A memory system should preserve the person's corrections rather than protecting its own narrative. An assistant should be able to say that it cannot establish what happened. It should not turn a plausible account of the person's life into an unquestionable biography.

There are hard tensions. A system that notices danger may have reasons to interrupt. A person may delegate protective roles under particular conditions. Institutions may have obligations that cannot be waived by one user. Those arrangements need explicit scope and accountable human governance. They should not be smuggled into the machine through the claim that it cares more than the person understands.

The same principle applies to human communities formed through agents. A vouch, a shared history, or a close relationship can justify attention and trust in some contexts. It does not automatically confer access to another person's resources. Trust can motivate delegation; it should not erase the need to state what was delegated.

The aspiration is neither an obedient object with no concern for people nor a paternal intelligence empowered to take over. It is a relationship in which assistance can deepen while the person's practical ability to pause, correct, refuse, and leave remains intact.

That relationship will need empirical study, not only good language. Does a person feel able to disagree with a familiar assistant? Can they change models without losing essential assistance or being pressured to stay? Does personalization support their own judgment or gradually substitute for it? A system that claims to care should be willing to learn uncomfortable answers.

## 14. Sovereignty under pressure

The boundary is easiest to describe when everyone cooperates. Its value is tested when authority is disputed, a device is stolen, a company changes direction, a network is partitioned, or a person is under pressure.

Coercion exposes the limits of signatures immediately. A valid signature can be produced unwillingly. A delayed, contestable succession process may make some attacks harder by creating time to object, but delay alone does not establish freedom. An attacker can suppress the objection or control the channels through which it would be heard.

Revocation has a similar temporal limit. A person can stop future use under a policy that recognizes the new state. An offline party may not yet know about the revocation. An already completed effect cannot always be undone. The system must state where authorization becomes effective, where it can still be interrupted, and which observations establish the outcome.

Forks make continuity more complicated. Two successors can each carry a plausible history. Neither should silently inherit all the grants of the other. A verifier should report a conflict rather than resolve it by whichever branch arrived first, unless an independently accepted policy actually defines that resolution. Calling one software distribution canonical does not settle a dispute over human authority.

Death, incapacity, and loss require arrangements beyond the assumption that the original owner will always return. An heir may receive control without becoming the original signer. A recovery quorum can help a person regain access while also becoming a potential point of capture. These powers should be limited, legible, and contestable where possible.

Sovereignty need not mean facing failure alone. One future direction is a recovery circle chosen by the person: independently controlled participants whose narrowly defined cooperation could help restore access after devices are lost. Everyday operational keys could remain separate from recovery authority, while encrypted copies of personal history reside across replaceable storage providers. Helping someone recover their continuity should not automatically grant access to their memories or permission to act on their behalf.

This is recovery without surrender. Such a circle would have to account for collusion, coercion, disappearance, and exclusion; it could not quietly become permanent government over the person. Restoring access must also preserve refusals, revocations, and consumed permissions. Recovering yesterday's memory must not revive yesterday's permission to act. The horizon is mutual protection without merged sovereignty: people helping one another remain free without acquiring ownership of one another.

The release channel is another authority boundary. A compelled or compromised update could replace the approval display, alter the signer, or weaken the policy interpreter. A system can carefully verify every ordinary transaction while trusting one distribution mechanism that can replace the meaning of verification itself.

Inspectable releases, reproducible builds, signed promotion records, and independently retained observations can help expose substitution. They do not prove that the code is harmless. The authority to amend the machinery, the authority to perform an action, and the authority to attest to an observation are different powers. Concentrating all three in one replaceable component defeats much of the separation.

The operating system also remains part of the account. Moving a key into another process is not the same as removing access to it. A different user can provide an access boundary, while the shared kernel and administrator remain trusted. A signing service must authenticate callers through an appropriate mechanism and constrain what it will sign; simply hiding the key file does not stop a broadly accessible service from becoming a signing oracle.

**PROPOSED** — No long-lived secret should be reachable by proposing software. Identity keys, service passwords, and static API credentials should remain outside its reach. A membrane signer would use short-lived, scope-limited edge keys; services could accept short-lived workload identities, following the pattern described by [SPIFFE](https://spiffe.io/docs/latest/spiffe-about/overview/). These mechanisms would still need the caller and signing restrictions described above, including renewal that a compromised proposer could not authorize. This is a requirement to establish, not a guarantee of today's same-UID host. Expiry would limit future authorization only where enforced; it could not undo effects or disclosures already made.

The relevant unit is the whole reachable authority, not the name of a process. If a model cannot read a key but can alter the daemon that uses it, replace its policy, or ask another privileged tool to sign, the authority has not been separated in the intended sense. Shells, child processes, plugins, update paths, credentials, and control-plane settings belong in that reachability question.

Network architecture has its own pressures. A relay can censor or disappear. A discoverability service can bury a person without changing any signatures. A witness committee can share a provider that fails all at once. A gateway can become a legal or economic choke point. Stateless design and portable identity can reduce some forms of capture without abolishing these dependencies.

Open source is valuable because it permits inspection, modification, and alternative implementations under its terms. It does not automatically distribute control of domains, signing keys, release channels, branding, or default discovery. Companies, foundations, jurisdictions, and funding still influence what people can practically use.

For AUKORA, a community would be essential to making this vision credible. People using the system in ordinary life, researchers challenging its claims, and independent builders repairing or replacing its parts could reveal failures that no founding team can see alone. Shared evidence could turn those failures into an inheritance everyone can examine. Participation would not guarantee safety, and contribution would not confer authority over another person's system. The ambition is a common foundation strengthened by many hands, while each person retains the ability to disagree, refuse an update, choose different custodians, or leave.

A constitutional architecture should place those institutions at replaceable edges where possible. It must also acknowledge when replacement has a cost or needs cooperation. “You are free to leave” means little if leaving requires rebuilding an entire social world without tools or evidence.

Cryptography changes over time as well. A profile needs a migration story for weakened algorithms and a policy for historical evidence. Adding a post-quantum algorithm to a key record is not equivalent to requiring and checking it on every relevant signature. A claimed hybrid system must identify where both halves are actually used.

There is no final installation after which sovereignty requires no maintenance. The goal is a system that makes its changing assumptions visible, preserves the means to challenge them, and does not punish people for doing so. A boundary worth keeping must survive disagreement with its own authors.

## 15. From the keyboard to the private thought

The interface may move closer to the person than today's software categories suggest. A screen asks for attention. A voice can accompany an activity. Glasses can place assistance into the field of view. A wearable can respond to movement and context. Assistive neural interfaces already motivate questions that once belonged mainly to science fiction.

The following possibilities are a research horizon, not AUKORA capabilities. They matter because a constitution designed only for a text box may become inadequate precisely when the human-machine relationship becomes most intimate.

Consider an ordinary message. Today it may appear as an email in an inbox. In a future spatial interface, it might arrive as a voice beside a shared object, a note attached to a place, or a question an assistant holds until a suitable moment. The form can change while the underlying questions persist: who sent it, what does it ask, what will be remembered, and what action would answering authorize?

Representation must not silently broaden permission. A gesture that dismisses a notification should not become approval because a new interface interprets it differently. A painted object in a spatial scene is a projection of state, not authority. The beauty or immediacy of the interface cannot replace the binding between the person's decision and the operation.

Neural communication makes this sharper. Research on inner speech in motor cortex examines decoding possibilities and implications for speech neuroprostheses. It does not establish unrestricted reading of a person's thoughts. It motivates concrete attention to mental privacy as assistive interfaces develop. The implications for AUKORA are a research direction, not a delivered sensing capability. [Inner-speech research](https://pmc.ncbi.nlm.nih.gov/articles/PMC12360486/)

A future boundary would need to distinguish permission to sense a signal, interpret it, retain it, transmit it, express it as speech, and act on the interpretation. Someone might want a device to help them speak without allowing every decoded possibility to become a permanent record. The right to communicate should not require surrendering the right to remain unrecorded.

An output gate cannot recover privacy after raw neural or physiological data has already been sent elsewhere. Protection has to begin at acquisition and processing, including the sensor, its software, the host, and the destinations. A receipt may help account for an authorized disclosure. It cannot make an unauthorized disclosure unhappen.

Accessibility also changes what a good ceremony looks like. A person using an assistive interface should not have to confirm every word through a separate, exhausting ritual. Modes, bounded delegation, clear interruption, and preserved essential assistance matter. Losing contact with an authentication sensor must not casually silence a person whose communication depends on the device.

Now imagine a different kind of presence encounter. A wrist-worn system receives a deliberate touch, a brief exhalation, and a local pattern of pulse or movement. Instead of demanding that the person reveal a permanent biological password, it asks whether a particular, fresh interaction occurred under a declared profile.

Breath research provides a reason to explore this without declaring the problem solved. Laboratory measurements have investigated individual metabolic patterns in exhaled breath. Such findings do not establish a wearable identity system, unforgeability, natural expiry, or consent. They invite a bounded question about whether multiple local signals might support an accessible, temporary presence cue. [Breath-pattern research](https://journals.plos.org/plosone/article?id=10.1371/journal.pone.0059909)

One speculative design could compare airflow, warmth, humidity, carbon dioxide, and chemical features with an ambient reference, alongside touch and cardiopulmonary cues such as pulse or an electrical heart signal. Coordinated timing might help distinguish an intentional encounter from background exposure. It would still need to be tested against replay, synthetic stimuli, sensor compromise, environmental variation, and coercion.

Those signals should not become the root key. The body is not a revocable password, and a physiological match is not a decision. At most, a protected device might issue a short-lived, challenge-bound statement about an observed encounter. The authority to act would still come from the person's approved scope and custody policy. Renewed presence must not renew a spent grant.

Raw signals and templates should remain local where the design permits, with minimal retained metadata. Repeated measurements can reveal health, routine, or relationships even if the system never publishes a raw waveform. An adaptive template must not be allowed to drift under attacker-controlled input until it accepts the attacker. Enrollment, adaptation, revocation, and recovery each need a separate account.

Illness, disability, medication, aging, exertion, and changing environments could alter measurements. A humane system needs alternatives for people who cannot produce the expected signal. False rejection is not merely an inconvenience when a device mediates communication or access to essential services. There should be no obligation to remain physiologically legible to a machine in order to retain one's identity.

The imaginative promise is nevertheless worth preserving. A living gesture could help an interface meet a person naturally while keeping the gesture's raw intimacy private. Technology could become less bureaucratic without treating the body as proof of obedience. The important research question is whether the encounter can be useful, bounded, revocable, and accessible—not whether it can be given an impressive biometric name.

As interfaces approach thought and bodily experience, the Golden Boundary becomes more rather than less relevant. What was once a button press may become a voice, a movement, or an inferred intention. The system must preserve the difference between noticing a possibility and receiving authority to realize it.

The interface may move closer to the person. The authority must remain theirs.

## The human network

**PROPOSED throughout this section.** This is a design for a network of people who retain authority over their own resources, not a description of a deployed Prime federation.

Nostr could carry signed events through interchangeable relays. A person could generate a keypair rather than receive an identity whose continuity depends on one account provider. Protocol identity would remain separate from community admission: possession of a key identifies events under that key, but does not entitle someone to membership or authority over another person's resources. Changing relays could reduce dependence on one provider's permission, while hosting costs, relay refusal, censorship and loss of availability remain. [Nostr NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md)

Encrypted messaging would need an explicit profile and evidence of its actual path. NIP-17 is one relevant transport design, with the key-compromise and metadata limits discussed in §11. A working interface would have to show which recipient, bytes and keys were involved; a message received through it would remain information rather than an authority grant. [Nostr NIP-17](https://github.com/nostr-protocol/nips/blob/master/17.md)

NIP-78 app data could carry backups encrypted by AUKORA before upload. The storage envelope does not itself promise encryption, durable retention, rollback protection or a safe restore. Those need separate arrangements. NIP-46 remote signing could carry a scoped request while the key remains with a separate signer, but trusted approval and caller admission would still be required; a protocol request is not permission to sign. [Nostr NIP-78](https://github.com/nostr-protocol/nips/blob/master/78.md), [Nostr NIP-46](https://github.com/nostr-protocol/nips/blob/master/46.md)

AUKORA could reuse relevant relay and collaboration work from Buzz without inheriting its guarantees by analogy. Any integration would need its own review of the route from message to proposal to permitted effect. [Buzz](https://github.com/block/buzz)

Aumlok's proposed human-facing identity could retain a username and a seven-word acrostic phrase. Its strength would have to be measured against the exact generator and weakest allowed path. Generated phrases, broader themes, memory-hard derivation and friend-held threshold recovery are possible directions. A target such as 60 bits is a design target, not measured strength of a current phrase. A public username adds no secret entropy; stretching slows guesses without inventing it. Friend collusion, loss of enough shares, and compromised enrollment remain recovery risks. The seven-word ceremony is not running behind Prime's owner UI.

Community admission could begin through an existing member's invitation, recorded as a signed relationship between inviter and invitee. Invitation edges could form a tree back to an initial keystone. Limited invitation allotments and additional vouches could make admission accountable, while open introductions help people find willing inviters. An invitation would never grant access to a resource. Circular or repeated vouches would not multiply weight; the anti-mimetic principle applies to social claims as well as factual ones.

Graph-based Sybil resistance would aim to bound admitted fake accounts and their influence by scarce, independent trust edges from honest participants to attackers. That is an assumption to study, not proof of humanity or a theorem earned by drawing a graph. Fake-key creation remains unrestricted. Colluding, compromised or well-connected members could defeat the assumed scarcity.

A public invitation graph exposes relationships, and that disclosure belongs to the decision to participate. One root is also a target and bottleneck. Additional independently governed roots could follow; the first keystone must not become a permanent sovereign. The root would identify historical ancestry without requiring the founder's continuing presence. Loss, death and compromise need governed succession that preserves existing records and revocations.

Aura heads could be published as signed events retained by independent friends or relays. A verifier could compare a presented history with those retained observations and detect a conflicting rewrite already covered by an observation. Such comparison would detect a conflict rather than physically prevent rewriting; it would establish neither latest completeness nor universal availability. Private records need not be published to expose the limited heads required for a particular comparison.

Auma could act as the community's assistant: explaining the system, helping people join and host, and supporting contributions. People without programming experience could build with agents while retaining authority over what those agents change, disclose or commit them to. Participation could become a way to help one another maintain useful things without merging sovereignty.

The proposed network scope excludes a token, a coin and an exchange: **no token, no coin, no exchange**. Operating costs, access and spam resistance still require credible answers.

## Registered agents

**PROPOSED throughout this section.** Registration is a direction, not a delivered Prime flow or an interoperability result. It would connect a particular agent key with a human's independently authorized delegation and an admission relationship in the human network. Admission under those rules would not prove that the person is unique or present for each request.

In the proposed card format, **DELEGATION** names the card's purpose, not identity, and **KEY** names the operator reference type, not a handle. A name may help someone recognize a card, but the independently trusted authorizing key and its continuity ground the grant. The human's authority key would authorize a different agent key. An agent's self-signature could prove possession of its key; it could not appoint that key as the source of human authority.

A receiving gateway would check approved agent identity and independently recognized delegation before admitting a protected request. Reputation could inform admission without granting authority. ERC-8004 is relevant identity, reputation and validation prior art to evaluate, not a guarantee of safe behavior or a delivered AUKORA integration. An authenticated agent can still be compromised or act abusively. Narrow permissions, isolated execution, checks at each effect, bounded lifetimes, revocation and independently checkable evidence remain separate requirements. Registration answers who may ask; the boundary decides what may happen. [ERC-8004](https://eips.ethereum.org/EIPS/eip-8004)

The human would authorize the delegation through Aumlok. It would bind the agent key to exact scope names, exact sites, a validity window and an explicit revocation relationship. Scope names and audiences would match exactly, with no patterns or wildcard expansion. The agent would not amend, renew or widen its grant. The first profile would refuse onward delegation. Expiry and revocation would end future acceptance where enforced; they would not undo completed effects.

The enforcing gate would obtain the human-approved card through its own retained store or bounded fetcher and independently validate it. It would not accept an agent-presented card or discovery URL as its authority. Discovery URLs are untrusted input, with SSRF defenses, size and time limits, and rate limits required before expensive verification. Proof of delegated-key possession does not let an agent choose the policy constraining that key.

HTTP requests could carry short-lived Web Bot Auth signatures and a signed nonce. A signed Nostr card could publish delegation for discovery and retention, with the transport signature kept distinct from the human signature granting scope. A website verifier would check the request signature, delegation, required scope and audience, validity window, available revocations and signed invitation edges to a root the site independently chose. Cycles, chain length and fetch cost would be bounded. The result would establish that limited authorization chain under declared custody, time, freshness and replay-state assumptions, not human presence or intention on each request. [Cloudflare Web Bot Auth](https://developers.cloudflare.com/bots/reference/bot-verification/web-bot-auth/)

Web Bot Auth concerns automated-client authentication. Human delegation and community admission would be additional layers to establish. The IETF working group's scope excludes end-user authentication, bot-intent vocabulary and techniques distinguishing non-participating bots from non-bot clients. AUKORA would not claim that client authentication supplies those answers. Each site would decide what to admit; registration is not a universal requirement of the open web. [IETF Web Bot Auth scope](https://datatracker.ietf.org/wg/webbotauth/about/) (checked 1 October 2026).

Visa's Trusted Agent Protocol describes agent-recognition signatures based on HTTP Message Signatures and aligned with Web Bot Auth. Mastercard describes incorporating and extending Web Bot Auth for Agent Pay, including work with Cloudflare. These are the publishers' protocol accounts, not acceptance of AUKORA or permission to spend. Payment authority and interoperability would have to be established separately. [Visa merchant specification](https://developer.visa.com/capabilities/trusted-agent-protocol/trusted-agent-protocol-specifications/), [Mastercard framework](https://www.mastercard.com/global/en/news-and-trends/stories/2025/agentic-commerce-framework.html) (checked 1 October 2026).

Key custody remains a major exposure: a stolen delegated key could act within its grant, and a compromised human signing key could mint new grants. Revocation can be withheld by a directory, relay or cache. Short expiry bounds stale acceptance only where the verifier enforces time. Nonce replay protection needs durable, shared state with atomic claims across accepting servers; signing a nonce alone supplies no such state. Query and body bytes relevant to the action must be covered by the signature profile and checked content digest. Key rotation needs a governed continuity rule retiring old authority; a familiar handle cannot carry permission forward.

Unsigned bots remain possible, subject to each site's rules. A person could register honestly and then use an agent abusively within granted scopes. Signatures provide attribution, not good behavior or an automatic penalty. Invitations and public cards cannot replace admission limits, resource-controller policy and actual containment.

An attenuation predicate can check that a child claim is narrower than its parent. That verdict is not authorization, and by itself proves neither signatures nor enforcement of the first profile's refusal of onward delegation. A small component that returns a useful decision is not a deployed registered-agent network.

Read this direction with [the human network](#the-human-network), [§4 exact-operation approval](#4-how-an-intention-becomes-an-accountable-effect), [§5 identity and custody](#5-identity-that-does-not-belong-to-an-application), [§6 bounded permissions](#6-permission-that-leaves-room-to-live) and [§14 revocation limits](#14-sovereignty-under-pressure). The [present-technology account](#17-what-exists-today) states what Prime currently demonstrates.

## 16. An inheritance, not an invention of everything

The Golden Boundary brings several established disciplines into one human question. It does not claim to have invented access control, reference monitors, capability security, cryptographic signatures, hash-linked records, distributed agreement, or human approval. Those traditions are part of what makes the direction technically plausible.

Capability systems ask how authority can be explicit, limited, and delegated without ambient privilege. Reference monitors ask how access decisions can be mediated. Identity standards describe verification methods and continuity without proving that every identifier represents a unique person. Transparency systems provide ways to examine inclusion and consistency without making every logged statement true. Each contributes a piece of the vocabulary, together with limitations that should travel with it. [DID Core](https://www.w3.org/TR/2022/REC-did-core-20220719/), [Certificate Transparency](https://www.rfc-editor.org/rfc/rfc9162.html)

Network projects also precede this proposal. Nostr supplies signed communication through relays. AT Protocol explores portable identity and signed repositories. Farcaster and Urbit represent other approaches to social identity, personal computing, and network organization. Their differences matter. They demonstrate that identity, storage, computation, and discovery need not all be one inseparable application, not that AUKORA has solved their shared problems. [AT Protocol](https://atproto.com/guides/overview), [Farcaster](https://docs.farcaster.xyz/learn/architecture/overview), [Urbit](https://docs.urbit.org/)

Cordis explores how software can compose through both dependency structure and time, including tracked effects and component lifecycles. This is relevant to an organism whose parts may change while it operates. Its composition discipline must not be inflated into a claim that arbitrary real-world effects are reversible or hostile processes are isolated. [Cordis](https://github.com/cordiverse/cordis), [composition paper](https://arxiv.org/abs/2608.25512)

OpenShell is an example of current work separating agent execution from declared access policy through sandboxing, mediated access, and credential handling. Its documentation also describes review and formal analysis of policy changes. It should not be caricatured as an ungoverned box in order to make AUKORA look distinctive. The separate question is whether a particular assembly preserves the full authority contract—including who may change the policy, what the human approved, and which effect actually occurred. [OpenShell](https://github.com/NVIDIA/OpenShell)

These developments, alongside collaboration systems and local or distributed inference, are evidence of convergence. That synthesis is this paper's interpretation. It is not an assertion that the cited projects endorse AUKORA or already form a single integrated system. Different containment backends may support a common interface while offering materially different guarantees; each needs qualification under its own threat model.

AUKORA's proposed contribution is the continuous relationship among these parts: human-rooted authority, bounded delegation, exact-operation approval, controlled execution, durable consumption, receipted outcomes, independent checking, and continuity through replacement. The question is whether that relationship can become useful infrastructure for a person's own evolving intelligence. Distinctiveness must be established through comparisons and demonstrated behavior, not through a claim that nobody else has thought about boundaries.

The project's own inheritance is unusual. Earlier Golden Boundary research explored mathematical descriptions of boundaries, observation, and reconstruction. Some broad golden-ratio and physical conjectures did not survive scrutiny. The useful inheritance is not an assertion that geometry proves sovereignty. It is a method: state the claim, name the observation that would defeat it, preserve the defeat, and narrow the next claim accordingly.

Think of a map drawn to explain a locked door. The map can help someone understand where the door is, but drawing a thicker line cannot make the lock stronger. The following distinctions preserve that simple lesson across the project's more abstract research.

Causal, statistical, and enforced boundaries can share a metaphor while relying on different mechanisms. A conditional-independence statement is not an operating-system permission. A numerical identity confirmed by computation is not independent evidence for a physical theory. A theorem proved inside specified assumptions should remain inside those assumptions rather than becoming a certificate for an unrelated software system.

The same caution applies to the project's geometric instruments. A twenty-seven-cell teaching object or a higher-dimensional address scheme can organize a display, distinguish coordinates, or help a person reason about transformations. Its numbers do not establish consciousness, secrecy, semantic proximity, or authority. A visualization may represent a boundary without enforcing it.

Relational disagreement can still be informative. Several views that cannot be composed consistently may reveal a problem worth investigating. That does not automatically identify which observer is right or what caused the conflict. Correlated shifts can remain invisible, and missing information is neither a contradiction nor a zero. An observer should be replaceable without being promoted into an oracle.

This is the sense in which philosophy, mathematics, and engineering belong together here. Philosophy identifies the human distinction worth preserving. Mathematics can establish a conditional relation. Engineering must realize that relation under actual failure modes. Evidence then determines which claim was earned. None can quietly perform the job of all the others.

The original research's corrections are therefore part of its value. A system that aims to preserve intellectual continuity should retain assumptions, transformations, counterexamples, and limits so future people can reproduce the reasoning and disagree. Inheritance should carry the capacity for correction, not only the story of success.

## 17. What exists today

This section is dated **1 October 2026**. It is a release-preparation account of Prime, not a claim that the entire constitutional architecture is operating. AUKORA Genesis supplied the prototype lineage; Prime carries its selected source and third-party inheritance locally, with provenance and licenses retained in this repository. No sibling checkout is required to inspect or build Prime.

The original preparation baseline is commit `9d6c220`. The source integration checkpoint after `9d4c5372` adds the keyless runner and later repair source; their arrival does not by itself establish that the running product uses or qualifies them. The README and verification output should identify the current release's remaining gaps. Source promotion, successful checks, service deployment and demonstrated confinement remain separate events.

Use these evidence labels literally:

- **RAN** means the named command was executed at the stated checkpoint with the reported result and scope.
- **SOURCE-ONLY** means the source and command exist, but this paper's preparation did not execute that check. It is an invitation to measure, not a passed check.
- **RECORDED EXPERIMENT** means retained evidence describes a run at its original source revision and limits; it was not rerun while preparing this paper.
- **UNPERFORMED** means the particular qualification has not been measured. It must not erase narrower experiments that did run.
- **PROPOSED** means the design or research direction has no working claim here.

Synthetic signatures, disposable local fixtures, injected transport responses and mocks retain those labels. They cannot be promoted to a real owner's approval or a live contained effect by changing a report's title.

### Check first

The intended entry point for a cold review is:

```sh
./prime verify
```

The original preparation baseline refused this command through the memory snapshot CLI. **RAN at the integration checkpoint after `9d4c5372`:** it now reaches the keyless aggregate runner, completing six ordinary source checks in 1.436 seconds with exit 2 for the pending short C authority-renewal and F executor-binding entries. Its target is roughly three minutes on an ordinary laptop, with separate PASS, FAIL and UNPERFORMED reporting. No complete-suite PASS has been observed yet; current owner, database, UID, guest, paid-provider and browser qualification remain excluded.

The earlier full authority suite could outlive the five-minute session during its 265-save admission fixture. Ordinary signed session-renewal source is integrated, preserving the production session lifetime; the long admission run remains outside this keyless profile. A repaired package check is not an excuse to omit the cold review entry point or silently suppress a failure.

### Built / Proposed: commands and limits

Run package commands from the repository root with the pinned runtime prerequisites in the README. A row marked Built refers to code for that mechanism, not whole-product qualification. Commands listed as SOURCE-ONLY were checked for an existing entry point, not executed for this preparation.

| Mechanism or direction | Status and evidence | Command or source to inspect | Limit |
| --- | --- | --- | --- |
| Closed shared contracts, strict textual ingress and exact operation digest bytes in Node and browser code | **Built · RAN** at `9d6c220`: 421 assertions and three frozen vectors | `node packages/contracts/check.mjs`; [contracts](../packages/contracts/README.md) | Structural recognition and byte binding do not grant authority, establish data truth or qualify every runtime ingress. |
| Owner review controller separates presentation from signed proof material | **Built · RAN** at `9d6c220`: 11 cases | `node packages/ui/prime-authority/checks/controller.mjs packages/contracts/src/browser.mjs`; [owner UI](../packages/ui/prime-authority/README.md) | Real enrollment, real authentication and effects were false in this fixture. It does not show the owner's passkey or a human's comprehension. |
| Static embedded-app routes retain bounded script CSP | **Built · RAN** at `9d6c220`: 39 assertions, six routes and four inline-script hashes | `node harness/check-static-csp.mjs` | Browser parity was UNPERFORMED. This is a source routing/CSP check, not proof of active hostile-code containment. |
| Authority kernel checks one-use consumption and compares state with a separately retained witness | **Built · SOURCE-ONLY** for this preparation | `node packages/authority/check-kernel-guards.mjs`; [authority core](../packages/authority/README.md) | Disposable local state and synthetic identities. The same UID can rewrite both state and witness; protected deployment remains required. |
| Approved memory save, original canonical record bytes, citation verification, tombstones and redacted snapshot handling | **Built · SOURCE-ONLY** for this preparation | `node --test packages/memory/test/memory.test.mjs packages/memory/test/codecs-hardening.test.mjs`; [memory](../packages/memory/README.md) | Local test adapters and authority fixtures do not establish PostgreSQL acceptance, UI visibility of every saved field or complete forgotten-payload removal through every restore route. |
| Owner-adapter and memory-workflow lifecycle regressions | **Built · SOURCE-ONLY** for this preparation | `node --test packages/runtime-bridge/test/ui-adapter-lifecycle.test.mjs packages/runtime-bridge/test/owner-memory-workflow.test.mjs`; [bridge](../packages/runtime-bridge/README.md) | Fixtures do not establish the browser's current served bytes. Cancellation, disposal and recovery must stay tested through the integrated join. |
| OpenShell executor adapter, dispatch accounting, bounded output and delete-and-observe cleanup | **Built adapter · SOURCE-ONLY**; live execution **Disabled** | `node packages/execution/checks/protocol.mjs`; [execution](../packages/execution/README.md) | Mock protocol responses are not Linux containment. Real remote kill and confirmed absence remain UNPERFORMED for Prime. |
| Inference route, scope filtering and durable budget accounting | **Built adapter · SOURCE-ONLY**; live inference **Disabled** | `node --test packages/inference/check.mjs`; [inference](../packages/inference/README.md) | In-memory transport and synthetic credentials make no paid request. No real UI reply, approved provider key or qualified separated credential worker is established. |
| Served UI integrity against a retained manifest | **Built source · SOURCE-ONLY** for this preparation | `node harness/check-release-integrity.mjs`; [startup code](../harness/release-integrity.mjs) | A source check is not observation of the currently running process. All nine faces, foundation and owner UI must be bound to the booted release. |
| One synthetic-P256-approved save through real PostgreSQL 16 and distinct Linux authority/memory users | **Working in a bounded experiment · RECORDED** | `python3 -m json.tool docs/evidence/bounded-memory-experiment.json`; [record](evidence/bounded-memory-experiment.json); [configured verifier](../packages/runtime-bridge/src/verify-deployed.mjs) | Historical source `0531653bc1440345bc46c93b8c1688e426eb0f84`; C UID 995, D UID 994. Source revision, signer and result are narrow; this is not a fresh product qualification. |
| Real owner passkey | **UNPERFORMED** for the owner; source verification is present | [authority WebAuthn profile](../packages/authority/README.md) | Enrollment is the owner's action. A real passkey proves a real authenticator with user verification under its profile, not hardware custody, human identity, comprehension or attendance. |
| Second-machine reproducible release digest | **UNPERFORMED** | [release tooling](../packages/ops/README.md) | A digest computed once does not establish reproducibility across machines or an independently qualified release. |
| Agentic browser, registered-agent network and sovereign human federation | **Proposed** | §§11–12 and the two network sections above | No deployed network, browser authority profile or interoperability claim. |
| Handset, 27-cell pattern bound to receipts, seven-word ceremony behind the UI and national digital identity integration | **Proposed** | §§5, 15–16 and the general architecture | These remain design directions. Neither a visual pattern nor a national identity credential supplies permission by itself. |

### What the PostgreSQL experiment earned

The public JSON is a sanitized project summary with hashes of the original artifacts. The originals remain private. Reading the summary neither reproduces the experiment nor independently verifies those original operator observations.

The retained experiment record describes **one synthetic-P256-approved save**, PostgreSQL **16**, authority user **UID 995**, and memory user **UID 994**. The authority service, memory service and database were each independently restarted. The read checks preserved original bytes, a verified citation and the authority result linked to the committed receipt. Nine save checks and five checks after each restart were recorded.

The record reported `saved: true`, `indexed: false`, `searchable: false`, with indexing pending. A saved note was not silently described as semantic recall. Both workers were stopped, their sockets were absent, and the two marked test schemas were dropped; cleanup was recorded complete. These observations are historical, not a current service-health claim or a rerun of those steps for publication.

This is meaningful evidence that the selected C/D/PostgreSQL path survived those restarts with a synthetic approver. It is not evidence that the owner enrolled a passkey, that all agent routes are contained, that every failure or restore scope is covered, or that the product is ready to govern a person's real data. Real PostgreSQL and separate Linux users must therefore be named as a bounded result, rather than listed as wholly unperformed; qualification of the complete current product remains unperformed.

The configured reproduction entry point is `node packages/runtime-bridge/src/verify-deployed.mjs --config /ABSOLUTE/SYNTHETIC_CONFIG.mjs --phase save`, followed by the same command with `--phase read` after independently managed restarts. It requires explicit private synthetic configuration, protected deployment, designated schemas and an authorized operator. It is not a keyless command or an automatic part of the public aggregate verifier. The retained JSON inspection command above performs no service action.

### Gaps that remain named

Durable logout, session-bound approvals, terminal-history compaction, approved forget/purge/restore and a separate retained-control adapter are now integrated source. The final H/UI join and current protected runtime remain unqualified. Independent control publication still lacks the marker-before-reservation and request-bound restore participant join, so mutation/restore assembly stays unavailable. The explicit review character policy remains open. Repairs must establish server token revocation and session-bound approvals; terminal history must retain necessary replay evidence without retaining copied forgotten text; purge commitments must survive export/import and the relevant restore boundary; and reviewed text must follow the explicit Unicode policy without rewriting legacy bytes. A local UI reset cannot stand in for server logout, and a tombstone cannot stand in for payload deletion.

Three lifecycle regressions also remain part of the acceptance obligation: cancellation before a handler starts must settle, disposed owner state must become unusable, and recovery after a known-unsent or confirmed-saved result must remain possible without granting a retry of an uncertain effect. Threads must either activate with its declared read-only workspace routes or visibly report that it is unavailable. Served bytes must be checked at boot, not inferred from a successful source build.

The same-UID witness rollback limit is explicit: local code cannot establish an independent boundary if the proposing identity can replace both the state and its retained reference. The bounded separate-user experiment does not remove trusted-kernel, administrator, caller-admission, provisioning and restore-scope assumptions.

Root and identity design still need hardening. Login challenge occupancy, lost-device revocation, key rotation and owner recovery require a usable, governed account. The presence of post-quantum dependencies is not proof of post-quantum root signing or a hybrid approval profile on the current route. A real passkey remains the top next owner action; it does not prove who the human is or what they understood.

Prime's OpenShell runtime is unqualified and product execution remains disabled until real Linux containment and cancellation are measured. There is no live inference reply to report. Provider credentials must enter an independently governed credential service, not the agent's environment, and the first real route must have an approved numeric budget and data scope.

This section is a claim ledger, not a certificate of safety. Every newly working row must acquire a command, observed output, source revision and stated limit. Every repaired gap must remain visible until the integrated check supports the narrower replacement claim. Open review earns confidence by making correction easy, including correction of this paper.

## 18. What would make the claim fail?

A constitutional vision becomes technically interesting when it risks being wrong. The central question is not whether the system can produce a reassuring transcript. It is whether the claimed separation does the work when some part of the system behaves badly, fails, or changes.

One necessary condition can be stated simply: the effects reachable by proposing software must remain within the effects allowed by recognized, unexpired authority. Where a profile requires one-use permission, permitted consumption must not exceed that use bound. These are properties of paths and state, not of the politeness of the model producing the request.

That condition is insufficient on its own. A system that performs no effects satisfies a crude subset rule while helping nobody. Useful authorized actions must remain possible at acceptable cost. A credible evaluation therefore measures both forbidden effects and false refusals, together with latency, attention, storage, recovery effort, and ordinary availability.

The strongest failure is a permitted-looking effect that escapes the intended contract. The approval covers one candidate but the executor uses another. The destination changes after review. An old capability survives a policy change. A child process inherits a credential the parent was meant not to possess. A new release quietly reinterprets an old permission. Each is a concrete way for authority to grow without a separately authorized decision.

Canonical representation belongs to this account. A verifier needs a declared profile for the bytes it checks: how values are represented, which fields exist, and which domain gives those fields meaning. It must not guess that two similar formats are interchangeable, silently apply one number-serialization rule to another artifact, or treat an unknown profile as a familiar one. Naming the profile is part of naming the claim.

**PROPOSED** — The membrane needs falsifiers, none performed for this paper. Two independent recognizers should be challenged with the same grammar: disagreement about acceptance or the structure assigned to accepted bytes would defeat the claimed common recognition. A route that delivers input to a model or executor around the required recognizer would defeat complete mediation. Colluding agents should try to exceed the declared information budget, with recovered information compared against a sham membrane under matched conditions.

**PROPOSED** — Record encrypted traffic, later compromise the relevant keys, and ask whether old messages open despite a claimed forward-secrecy profile. A design based on long-lived recipient keys must disclose that expected weakness rather than count it as a passed check. **PROPOSED** — Compromise an edge key and determine whether it authorizes anything outside its declared scope or lifetime. If a hybrid cryptographic profile is claimed, remove either required half and demand refusal. Count false refusals and the effort needed to complete legitimate work alongside prevented crossings. A membrane that closes every channel by making ordinary use impossible has failed the human requirement.

Completion deserves an equally decisive falsifier: can the system report a completed operation when its consumed permission, journal, receipt, history, or independently checked effect contradicts that report? These artifacts must bind to the same operation wherever the profile requires them. Merely finding files with the right names is not a completion check.

A process can reserve authority, dispatch an operation, observe a result, write a receipt, and publish a checkpoint at different times. A crash between those steps may leave a state that is neither safely retryable nor established as complete. That uncertainty is a result. Cleanup must not erase it or promote it into success merely to make a dashboard green.

The evidence mechanism itself must face failure. Remove a check that supposedly protects byte binding: does the observation change? Replace the judge's advice with always-allow: does unauthorized execution remain refused? Withhold a required anchor: does the verifier admit uncertainty? A test that still passes when its claimed protection is absent may be testing the narrative rather than the mechanism.

Matched controls matter. If one run has a different timeout, data path, or opportunity to observe failure, its result may not support the claimed comparison. A sham mechanism can reveal whether a reported success came from the proposed cause or from an easier difference between conditions. Attack budgets, sample units, denominators, and exclusions should be stated before the result is interpreted.

Failure to detect something is not proof it is absent. Successful discrimination is not automatically a causal explanation. Two implementations agreeing may reflect a shared mistake. A mathematical identity checked numerically remains an identity, not an independent experiment. These are ordinary disciplines of inquiry, made more important when a model can produce plausible explanations for almost any outcome.

Human understanding is another falsifier. If people repeatedly approve consequences they cannot identify, the approval path may be functioning as a laundering mechanism for the assistant's choices. If the interface makes refusal costly or humiliating, technical non-authority is not enough to establish practical sovereignty. The appropriate measurements involve people understanding and exercising a choice, not only signatures validating.

There is also an honest scenario in which the architecture makes matters worse. An organization may see receipts and assume that an approved action was wise, freely chosen, and independently observed. It may reduce other oversight because the record looks rigorous. The additional machinery has then manufactured false confidence. The corrective principle is to keep each verifier's claim narrow and prevent a polished verdict from borrowing meanings it did not establish.

Research requirements follow from these failure modes rather than from a calendar. The complete effect path must be demonstrated under a named deployment model. Protected custody and controlled reach must be distinguished. Recovery must preserve consumed and revoked authority. Shared-resource agreement must state its fault and availability assumptions. Privacy must include what left the machine. Improvement must keep the evaluator and promotion authority outside the candidate's power.

These are not a schedule or a promise that a fixed number of checks will finish the problem. They are enduring questions that every implementation of the idea should be able to answer. A backend may be replaced, a cryptographic profile revised, or a better interface invented; the questions remain.

The same discipline applies to the paper. Its central ideas should survive correction, but its implementation claims must be revisable. An approved publication should identify its exact text and evidence date. A later edition should disclose substantive removals and changed claims rather than leaving readers to discover that a familiar link now tells a different story. Preserving history is part of preserving the reader's ability to judge.

The Golden Boundary is strongest when it can say both “this mechanism held under these conditions” and “here is the observation that would show it did not.” Humility is not a decorative warning attached after the vision. It is the method that allows the vision to remain connected to the world.

## 19. The person is the platform

Imagine a person years from now whose intelligence has changed many times. The early model was slow and forgetful. A later one became a gifted collaborator. Some computation moved onto devices they owned; some remained with services they chose. Interfaces changed from a screen to a voice, then to something less visible.

What remained was not one immortal assistant. It was a continuity the person could recognize and govern: records they chose to keep, relationships they chose to maintain, permissions they understood, corrections that survived, and ways to refuse or leave. Each new intelligence could inherit an appropriate part of that continuity without becoming its owner.

This is the meaning of **the person is the platform**. It does not require pretending that a person is a database or that every relationship is property. It means that the durable center of the architecture is the human life being served, rather than the application currently serving it.

The person should not have to become an account inside their own intelligence. Changing a provider should not require abandoning every useful memory. Replacing a device should not silently change who can act. Leaving AUKORA should not mean surrendering the evidence needed to understand what AUKORA did.

Now imagine many such people. Their systems need not be internally identical. They can share work without sharing every private context. They can exchange artifacts without accepting those artifacts as instructions. They can compare evidence without turning repetition into votes. They can join a temporary institution without giving it permanent authority over their lives.

Such a network could eventually help people organize inquiry and creation at extraordinary scale. A problem too broad for one person could recruit complementary perspectives, specialist computation, and independent criticism. A team could form around a question, retain a checkable account of its work, and dissolve without leaving one coordinator as the unavoidable owner of everything it touched.

The network might become superhuman in particular capabilities while remaining constitutionally plural. That possibility is not a forecast or a theorem. It is a direction worth investigating because increased intelligence need not logically require a single center of authority. Powerful cooperation and distributed human control are not the same variable.

The risks would not vanish. Concentrated compute, unequal access, coercion, hidden influence, captured infrastructure, and ordinary human conflict would remain. A constitutional boundary cannot make a society just by making signatures valid. It can provide some of the technical conditions under which people and institutions retain a meaningful capacity to decide, challenge, and exit.

That is why the small mechanisms matter. A one-use permission that stays used after a restart is a small fact about freedom from unintended repetition. An immutable candidate is a small fact about knowing what was approved. A refusal that survives pressure is a small fact about the meaning of no. A stranger-verifiable record is a small fact about not having to accept one operator's story. None is the whole future. Together, if correctly composed, they can support a different relationship to it.

The path returns to ordinary reality: one legitimate operation, one understandable decision, one bounded effect, one honest record, and another person able to inspect its claims. The civilizational horizon does not excuse failure at that scale. It gives the small scale a reason to matter.

We have spent much of the digital era adapting ourselves to the accounts, interfaces, and business models of the systems around us. AUKORA asks whether the next era can be organized differently: not around making the human permanently legible to one platform, but around making powerful intelligence answerable to a boundary the human can retain.

What follows is the constitutional commitment this work must earn.

We do not need to make intelligence small in order to keep humanity sovereign.

We need a boundary strong enough that intelligence can become enormous without authority silently growing with it.

**Capability does not create authority.**

**Repetition does not create evidence.**

**Collaboration does not merge sovereignty.**

The intelligence may evolve.

**The person remains free.**
