# Phalanx's Coherence plan: Conduit's check (11/22, 4:15 PM)

The coordinator's plan (coordinator/PLAN.md, 402 lines, complete) was read in its design, engine, build-order and question
sections. What holds, and what needs correcting before it is used:

1. **It meets the owner's decisions.** The original Coherence is never written; Phalanx's engine copy changes only two outputs
   (review data as JSON instead of compiled pages; data-only book, ledger and statement files instead of per-recipient viewers),
   about 80 lines, with no change to the calculation, the overlay reader or any parser. Decisions are records; the overlay the
   engine reads is generated from them in the worker's workspace and fingerprinted. Book, ledger and statements per entity are
   database tables and views tied to the ledger, reproducing the 11/20 exercise. The proof has the layers the owner asked for.
2. **Viewer copies: settled.** Its question 6(b) and build step 0 propose filtering and later removing the viewer pages in
   Phalanx's storage. The owner decided they are not a concern (baffe84b): leave them, and drop step 0's patch.
3. **Retention: the owner's call.** Its question 6(a) recommends ten years; the official rules are on the HIPAA list (HIPAA 6;
   CMS call recordings 6; CMS plan records and audit right 10).
4. **The 11/11 run (its question 3):** the plan calls Phalanx's 11/11 statements an undistributed accounting exercise and would
   leave them out of production's sent history. The board records 11/11 as Phalanx's official run, carried and recorded sent in
   Google (its statements were headers with no lines). Checked: the reference computer's own sent folder holds 8/31, 9/30, 10/12
   and 11/02 only. So the record differs between the two places; with no lines it changes no money, but which is right is the
   owner's to say.
5. **The engine copy's home:** the plan keeps it in a private `coherence-engine` repository in Nusear's organization, which does
   not exist yet (GitHub's organization is still to be set up). Until then it can live as a branch in a Nusear-private local
   repository; never in Coherence's own folder.
6. **The live proof** it builds on now passes on the cleaned branch (checked today, after fixing the engine-commit archive bug).
