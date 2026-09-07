# ATTACK VECTOR DETECTION PLATFORM

**A security watcher for your websites.** It looks at the outside of a website
the way a security researcher would, shows you what it found in a private
dashboard in your browser, and sends you a Telegram message when something
changes.

> This file is written for everyday users. No programming knowledge is needed
> to read or use it. Developers: the deep technical guide is in
> [docs/HANDOVER.md](docs/HANDOVER.md), and there is a wish list for you in
> section 10. A Persian copy of this file is here:
> **[README.fa.md](README.fa.md)**.

---

## 1. What is this, in one paragraph?

You give the platform the name of a website you own, for example
`example.com`. It then quietly walks around the outside of that website and
reports back: which website names belong to it (like `blog.example.com` or
`shop.example.com`), which of them are online right now, which technical
"doors" (ports) are open on the servers behind them, and what has changed
since the last time it looked. Everything it learns is shown in a private
control panel in your browser and can be turned into a clean report (web page,
PDF, or spreadsheet). If something new appears -- a website name that did not
exist yesterday, or a door that was closed and is now open -- the platform
sends a Telegram alert to the person in charge.

Think of it as a night guard for your website's building: it does not break
into anything, it only notes which doors and windows it can see, and it
tells you when a new one appears.

## 2. What can it do?

| What you get | In plain words |
|---|---|
| **Find website names** | Discovers the addresses that hang under your main domain, using many public sources at once. |
| **Check what is alive** | Tests which of those addresses really answer right now, and which are dead. |
| **Check open doors** | Scans the server's ports and names the services behind them. |
| **Watch for changes** | Compares every check with the previous one and highlights what is new or gone. |
| **Telegram alerts** | Sends a message to your Telegram the moment something important changes. Each website you watch can have its own Telegram setting. |
| **Clean reports** | One click gives you a report as a web page, PDF, CSV, or JSON -- with a built-in proof that the report was not modified afterwards. |
| **Private dashboard** | A dark, security-themed control panel in your browser. Start checks, read results, manage settings -- all without a terminal. |
| **Scheduled watching** | Tell it "check every night" and it does the round by itself. |
| **Works with zero API keys** | The basic features need no accounts and no keys anywhere. Optional free keys unlock extra sources (section 8). |
| **Tidy storage** | Old logs are compressed and pruned automatically, so the tool never fills your disk. |

## 3. What do you need before starting?

- A computer or small server with **Docker** installed. Everything else the
  platform needs is downloaded and built automatically on first start.
- That is all. No database to install, no accounts to create, no keys to buy.

## 4. Start it in 3 steps

Open a terminal in the project folder and run:

```bash
cp .env.example .env
```

Then open the new `.env` file with any text editor and set one line -- the
login password for the dashboard:

```
DASHBOARD_TOKEN=changeme
```

Replace `changeme` with a long password of your choice. (If you want Telegram
alerts, also paste the bot token here -- see section 7. You can skip that for
now and do it later.)

Now start the platform:

```bash
docker compose --profile dashboard up -d --build
```

The first start builds the tool boxes, so give it a few minutes. After that it
starts in seconds. Open **http://127.0.0.1:8080** in your browser, paste the
same password in the top-right box, and you are in.

## 5. Using it day to day (the whole journey)

### Step 1 -- Tell it where to send alerts (one time)

Open the **SETTINGS** page. There is one box that asks for your **Telegram
user ID** -- a number like `123456789`. Type your number and save. That is the
only thing you ever have to enter: no bot creation, no chat setup, just your
number.

Don't know your number? Open Telegram, search for `@userinfobot`, press
**START**, and it replies with your number. Copy that number into the box.

### Step 2 -- Add the website you want to watch

Open the **TARGETS** page and add your website, for example `example.com`.

This page is also where **each website gets its own Telegram setting**. For
every website you can choose:

- **inherit global** -- use the Telegram ID from Settings (the usual choice);
- **its own ID** -- send this website's alerts to a different Telegram number
  (useful when different people are responsible for different websites);
- **muted** -- no Telegram alerts for this website at all.

Every website is independent. Changing one website's alert setting never
touches the others.

### Step 3 -- Press START

Open **RUN CONTROL**, type the website name, and press **START**. You watch
the progress live in the browser, step by step. A full check takes from a few
minutes to about an hour depending on how big the website is.

### Step 4 -- Read what it found

- **RESULTS** shows everything that was discovered, with filters and
  "new since last time" badges.
- **REPORTS** has a **GENERATE NOW** button. One press gives you a tidy
  report as a web page or PDF, listing everything with proof that the report
  file has not been modified.

### Step 5 -- Let it watch for you (optional)

In **RUN CONTROL** you can set a schedule, for example "every night at 3".
From then on the platform checks the website by itself and, if something
changed, a Telegram message is waiting for you in the morning.

## 6. Telegram alerts -- the short version

- **You** set **only your Telegram user ID** (a number). Nothing else.
- The **bot token** -- the one-time key that lets the platform talk to
  Telegram -- is pasted into the `.env` file once by the person who installed
  the platform (section 7). Everyday users never see or touch it.
- **Each website can override the default**: its own Telegram ID, or "no
  alerts for this one". The website's own setting always wins over the global
  one.
- Press **SEND TEST** on the SETTINGS page and a test message should arrive
  within seconds. If it does not, the platform tells you honestly what went
  wrong instead of failing silently.

## 7. For the person who installs the platform (one-time, 5 minutes)

Two things go into the `.env` file:

| Line | What it is | Where to get it |
|---|---|---|
| `DASHBOARD_TOKEN` | The dashboard login password. | You choose it yourself. Make it long. |
| `TELEGRAM_BOT_TOKEN` | Lets the platform send Telegram messages. | In Telegram, talk to `@BotFather`, send `/newbot`, follow the two questions, and copy the long token it gives you. |

That is the whole installation surface. Everything else -- settings, keys,
targets, schedules -- is managed later from the dashboard pages by normal
users, without touching any file again.

## 8. API keys -- not needed, but nice

The platform is built to work **with no keys at all**. A few public
information sources give deeper results if you create a free key on their
website. Without a key those sources are skipped, and the platform **says so
openly** in the results -- it never hides that something was skipped. You can
add or remove keys any time on the **API KEYS** page; the change takes effect
on the next check, with no restart. The full list of optional keys and what
each one unlocks: [docs/api-keys.md](docs/api-keys.md).

## 9. Rules you must follow

- Only point the platform at websites **you own** or have **written
  permission** to test.
- The platform enforces this itself: it refuses to scan anything that is not
  on its allow-list, and it re-checks the allow-list before every step.
  Out-of-scope targets are a hard stop, not a warning.
- Scanning other people's websites without permission is illegal in most
  countries. The tool is built to make the honest path the easy path -- use
  it that way.

## 10. Ideas for developers -- what would make this platform even better

If you are a developer looking for something useful to build, any item on
this wish list would be a real improvement. The items are ordered by how much
value they would add for the least work. The technical guide
([docs/HANDOVER.md](docs/HANDOVER.md)) explains how every part works today,
so you can see exactly where a new piece would plug in.

1. **Spreading requests over several outgoing IPs** -- big websites sometimes
   block a scanner that asks too much from one address. Rotating outgoing
   addresses (a proxy or IP pool) would keep long checks running smoothly.
2. **Built-in common-weakness checks** -- after finding the doors, the
   platform could automatically try the industry-standard list of the most
   common well-known weaknesses (the OWASP Top 10 for websites and for APIs)
   and attach a short, readable explanation of each hit to the report.
3. **Automatic watch-list growth** -- when the platform discovers a new
   website name under your domain, it could offer to add it to future checks
   with one click, so the watch list grows by itself.
4. **Risk scores** -- rank the findings from "just interesting" to "fix this
   today", so the owner knows what to do first without reading everything.
5. **Charts over time** -- draw the history week by week: how many website
   names, how many open doors, what appeared and when. Change-over-time
   pictures make problems obvious at a glance.
6. **More alert channels** -- Slack, Discord, plain email, or generic
   webhooks, next to the existing Telegram alerts.
7. **More languages for the dashboard** -- the interface is English today; a
   language switch (for example Persian) would open it to more teams.
8. **Several user accounts** -- separate logins with roles (viewer, operator,
   admin) and a record of who started which check and changed which setting.
9. **One-file installer** -- a single script that prepares a fresh server
   from zero to a running dashboard with no manual steps.

Small fixes and ideas of your own are welcome too -- the code is organized so
that a new feature is usually one new module plus one dashboard panel.

## 11. Advanced: the command line

The dashboard can do everything, but for scripting there is also a
command-line interface:

```bash
./recon.sh run example.com        # run one full check now
./recon.sh status example.com     # show what the last check did
./recon.sh report example.com     # rebuild the report bundle
```

## 12. Where to look next

| File | For whom | What is inside |
|---|---|---|
| [README.fa.md](README.fa.md) | Everyone | This whole file in Persian. |
| [docs/HANDOVER.md](docs/HANDOVER.md) | Developers | The full engineering guide: architecture, every part explained, how to extend safely. |
| [docs/api-keys.md](docs/api-keys.md) | Users | Every optional key, where to get it, and what it unlocks. |
| [docs/security.md](docs/security.md) | Operators | How tokens and secrets are handled, and what to do if one leaks. |

## 13. Legal

Run only against targets you are authorized to test. Unauthorized scanning of
systems you do not own or do not have permission to test is illegal. The
platform's allow-list enforcement exists to protect you; do not fight it.
