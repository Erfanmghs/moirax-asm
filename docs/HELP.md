# The Complete User Guide

**Attack Vector Detection Platform -- step-by-step help for everyday users.**

This guide explains every feature, how to use it correctly, and shows real
examples you can follow along with. No programming knowledge is needed.
(Developers: the engineering guide is `docs/HANDOVER.md`.)

---

## 1. What does this platform do?

You give it a website you own -- for example `example.com`. The platform then:

1. **Finds website names** that hang under your domain, like
   `blog.example.com` or `shop.example.com`, using many public sources.
2. **Checks which of them are alive** right now.
3. **Checks which doors (ports) are open** on the servers behind them.
4. **Compares** every check with the previous one and marks what is new.
5. **Sends you a Telegram message** when something important changes.
6. **Builds a clean report** you can open in your browser or share as PDF.

Think of it as a night guard for your website's building: it does not break
into anything -- it only notes which doors and windows it can see, and tells
you when a new one appears.

**One rule above all:** only point it at websites you own or have written
permission to test. The platform enforces this itself -- anything not on its
allow-list is refused, hard.

---

## 2. Before you start

You need exactly one thing:

- A computer or small server with **Docker** installed.

Everything else is built automatically on first start. No database, no
accounts, no paid services.

---

## 3. Install in 3 steps

```bash
# 1) copy the example configuration
cp .env.example .env

# 2) open .env and set your dashboard login password
#    DASHBOARD_TOKEN=changeme   ->  replace changeme with a long password
#    (Telegram bot token goes here too -- see section 7)

# 3) start the platform
docker compose --profile dashboard up -d --build
```

The first start builds the tool boxes -- give it a few minutes. After that it
starts in seconds.

Open **http://127.0.0.1:8080**, paste your password in the top-right box,
press **SET**. You are in.

> **Example:** if your password is `my-secret-42`, you put
> `DASHBOARD_TOKEN=my-secret-42` in the `.env` file, start the platform, then
> type `my-secret-42` into the top-right box of the dashboard.

---

## 4. Your first check (from zero to results)

**Step 1 -- set your Telegram receiver.** Open the **SETTINGS** page. In the
TELEGRAM field, type your own username -- `jackjohns`, `@jackjohns` -- or
your numeric id, like `123456789`. Press **SEND TEST NOTIFICATION**. A test
message should arrive within seconds. If it does not, the platform tells you
exactly what to do next (see section 7).

**Step 2 -- register your website.** Open the **TARGETS** page. Type the
website name (`example.com`), press **LOAD**, optionally give it a
description like "main company site", and press **SAVE PROFILE**.

**Step 3 -- start the check.** Open **RUN CONTROL**, type `example.com`,
press **START**. The live log shows each step as it happens. A full check
takes from a few minutes to about an hour depending on the size of the site.

**Step 4 -- read the results.** Open **RESULTS** and pick your target in the
top bar. Every discovered address is listed with filters and "new" badges.

**Step 5 -- get the report.** Open **REPORTS**, type the target, press
**GENERATE NOW**, then press **OPEN** next to `report.html` (or download the
PDF).

---

## 5. Understanding the results

| Column | Meaning |
|---|---|
| HOST | A website name that was found, e.g. `api.example.com` |
| IPS | The server address(es) it resolves to |
| ALIVE | Did it answer when we knocked? (green = yes) |
| SOURCES | Which information sources found it (more than one is normal) |
| TAGS | Labels like `dev` or `stage` when the name hints at them |

Above the table, **diff badges** summarize the change since the previous
check, for example: `+3 hosts` (three new website names appeared),
`+1 port` (a new door opened), `-2 hosts` (two names disappeared).

**Example:** last week `old-admin.example.com` existed; this week the RESULTS
badge shows `-1 hosts` and the DIFF VIEW lists it under "removed". That is
exactly the kind of forgotten site that should be shut down -- and now you
know about it.

The **SOURCE COVERAGE ANALYTICS** table shows which source contributed what,
so you can see if adding an API key (section 9) would actually add coverage.

---

## 6. Telegram alerts -- the short version

- **You** set only your own **username or numeric id**. That is all.
- The **bot token** (the key that lets the platform talk to Telegram) is set
  once by the installer in the `.env` file. Everyday users never see it.
- **Each website can have its own receiver**: give one website a different
  Telegram username, or mute it entirely -- on the TARGETS page.
- **Backup tokens**: in `.env` you can list extra bot tokens separated by
  commas. If a token stops working, the platform **switches to the next one
  automatically** -- no human needed.
- If a personal username does not deliver on the first try: open your bot in
  Telegram and press **START** once. The platform learns your chat
  automatically and the next SEND TEST arrives. Public channel handles
  (`@teamname`) work immediately once the bot is a member.

**Troubleshooting table (SEND TEST results):**

| What you see | What it means | What to do |
|---|---|---|
| TEST SENT | Everything works | Check your Telegram |
| no bot token is provisioned | The installer step is missing | Create a bot with @BotFather (`/newbot`), put the token in `.env` |
| every token was rejected | Token(s) invalid/revoked | Paste a fresh token; backups were already tried automatically |
| chat not found | The account never said hello to the bot | Open your bot in Telegram, press START, try again |
| telegram unreachable | Network problem | Check this machine's internet/proxy, try again |

---

## 7. For the installer (one time, 5 minutes)

Two lines in the `.env` file:

| Line | What it is | Where to get it |
|---|---|---|
| `DASHBOARD_TOKEN` | Dashboard login password | You choose it -- make it long |
| `TELEGRAM_BOT_TOKEN` | Lets the platform send Telegram messages | In Telegram: talk to `@BotFather`, send `/newbot`, answer two questions, copy the long token. Extra tokens separated by commas act as automatic backups. |

Everything else is managed later from the dashboard by normal users, without
touching any file again.

---

## 8. Per-website settings (TARGETS)

Every registered website can have its own:

- **Telegram receiver** -- different username, or muted (`inherit global`
  means "use the global one from SETTINGS");
- **digest threshold** -- group alerts into one summary above N new findings;
- **budgets** -- time limits for the check's phases (leave empty unless the
  site needs special treatment);
- **proxy pool** -- its own outgoing IP rotation list (section 10).

**Example:** your team watches `shop.example.com` and `blog.example.com`.
Give the shop's profile the ops-team Telegram username and the blog's profile
the content-team username -- each side gets only its own alerts.

---

## 9. API keys -- not needed, but nice

The platform works with **zero keys**. A few public information sources give
deeper results with a free key. Without a key those sources are skipped, and
the platform **says so openly** in the results -- it never hides a skip.

Open **API KEYS**: every row explains which module uses the key and what
happens without it. Paste a key, press SET -- it takes effect on the next
check, no restart. Keys are masked after saving.

The full key-by-key matrix with links to get each one: `docs/api-keys.md`.

---

## 10. Spreading the load -- IP rotation (proxy pool)

Big websites sometimes block an address that asks too many questions. The
platform can spread its outgoing requests over a **pool** of proxies, so no
single address carries the whole scan.

**How to set it up (SETTINGS):**

1. Get one or more HTTP or SOCKS5 proxies (your provider gives you URLs like
   `http://user:pass@proxy-host:8080`).
2. Paste them into **PROXY POOL**, separated by commas:

   ```
   http://user:pass@proxy-a:8080, http://user:pass@proxy-b:8080, socks5://proxy-c:1080
   ```

3. Press **SAVE SETTINGS**. That is all.

**What the platform does with it:**

- Before a check starts, **every entry is health-checked**. If one is
  unreachable, the check refuses to start and names the bad entry (with its
  password masked) -- you are never left guessing.
- During the check, discovery steps go out through the entries **in turn**
  (round-robin): step 1 uses proxy A, step 2 proxy B, step 3 proxy C, step 4
  proxy A again, and so on.
- Each step's assignment is written to the run's
  `logs/proxy-rotation.json` -- you can always see exactly which proxy was
  used by which step. Passwords are masked everywhere.
- **Per website:** the TARGETS page accepts its own pool, so one site can use
  a dedicated set of proxies while everything else uses the global list.
- Honest limits: the port-scanning step uses a different networking method
  and runs direct (the run log says so explicitly); DNS resolution has its
  own dedicated resolver lane.

---

## 11. Automatic checks (scheduler)

In **RUN CONTROL**, set an interval in minutes (10 is the minimum) and tick
**enabled**, then press SAVE. From now on the platform checks the website by
itself, and if something changed, a Telegram message is waiting for you.

**Example:** interval 720 = twice a day. Set it in the evening; in the
morning you only read what is new.

---

## 12. Reports

**REPORTS** page: press **GENERATE NOW** and the platform builds:

- `report.html` -- a clean page you can open in the browser and share with
  your team;
- `report.pdf` -- the same, printable;
- `export.csv` / `export.json` -- for spreadsheets and further tooling;
- `report.md` -- plain text for wikis.

Every bundle carries a **SHA-256 manifest**: a built-in proof that the files
were not modified after generation.

---

## 13. Checking several websites at once (FLEET)

Register each website on the TARGETS page first. Then open **FLEET**, type
`all` (or a comma-separated list like `shop.example.com,blog.example.com`),
choose how many run in parallel (1-8), and press **RUN FLEET**.

Each website runs in its own isolated workspace with its own profile -- one
site failing never blocks the others, and the ledger shows exactly what
happened to each member.

---

## 14. Storage -- logs can't eat your disk

Housekeeping runs automatically after every check: old run snapshots are
pruned (default: newest 20 kept), live logs are compressed when they exceed
their size cap, and there is a total cap per website. Your result data,
reports and run history are never touched. All knobs live in
**SETTINGS -> STORAGE / LOG RETENTION**.

---

## 15. Safety and legal rules

- Only scan websites **you own** or have **written permission** to test.
- The platform refuses anything not on its allow-list, and re-checks before
  every step. That enforcement exists to protect you.
- Unauthorized scanning of other people's systems is illegal in most
  countries. Use the honest path -- it is also the easy path.

---

## 16. Questions people actually ask

**Q: Does a check change my website?**
No. The platform only looks from the outside -- the way any visitor's browser
would. It does not log in, does not submit forms, does not write anything.

**Q: How often should I check?**
Twice a day is a good start for a normal company site. Use the scheduler.

**Q: A check failed halfway -- do I start over?**
No. Press RESUME; the platform continues where it stopped.

**Q: I found a website name I do not recognize in my results.**
That is the platform doing its job. Check whether it should exist. If not,
shut it down -- an unknown live name is exactly how incidents start.

**Q: Where do the "sources" in RESULTS come from?**
Public information sources (certificate logs, search engines, DNS archives
and similar). Adding a free API key wakes up more of them -- see section 9.

**Q: Can two people use the dashboard?**
Yes -- share the dashboard password for now; separate accounts with roles
are on the roadmap (README, section 10).

---

## 17. Little dictionary

| Word | Plain meaning |
|---|---|
| Subdomain | A website name under your main one, like `blog.example.com` |
| Port | A numbered "door" on a server that services listen behind |
| Alive / dead | Did the address answer when we knocked? |
| Diff | What changed since the previous check |
| Digest | One grouped message instead of many single alerts |
| Proxy pool | A list of outgoing addresses the platform rotates through |
| Breaker | The built-in fuse: if a source misbehaves, the platform slows down instead of crashing |
| Scope | The allow-list of targets the platform may ever touch |
