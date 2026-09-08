# ATTACK VECTOR DETECTION PLATFORM

**A security watcher for your websites.** It looks at the outside of a website
the way a security researcher would, shows you what it found in a private
dashboard in your browser, and sends you a Telegram message when something
changes.

> This file is written for everyday users. No programming knowledge is needed
> to read or use it. Developers: the deep technical guide is in
> [docs/HANDOVER.md](docs/HANDOVER.md), there is a wish list for you in
> section 10, and the step-by-step user guide is
> [docs/HELP.md](docs/HELP.md) (also available as the HELP panel inside the
> dashboard).

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

- A computer with **Windows 10/11, macOS, or Linux**, about **4 GB of free
  memory** and **10 GB of free disk space**.
- An **internet connection**.
- A **GitHub account that has access to this repository**. The repository is
  private: either you are its owner, or the owner has invited your account.
- About **10 minutes** the first time (mostly one-time downloads). Every
  start after that takes a few seconds -- see 4.5.
- Nothing else. No database to install, no accounts to create, no keys to
  buy. The two free tools the platform needs (Git and Docker) are installed
  in the next section, step by step.

## 4. Install it from zero to hundred

This section takes you from an empty computer to a running dashboard. Every
step is one-time work; after step 4.6 you only use the browser.

### 4.1 Install Git -- the tool that downloads the code

- **Windows**: download the installer from <https://git-scm.com/downloads>,
  run it, and keep pressing Next until it finishes.
- **macOS**: open Terminal, type `git --version`, and press Install in the
  window that appears.
- **Linux (Ubuntu/Debian)**: run
  `sudo apt update && sudo apt install -y git`.

Check that it worked: open a **new** terminal and run `git --version`. It
should print a version number.

### 4.2 Install Docker -- the tool that runs the platform

- **Windows / macOS**: download **Docker Desktop** from
  <https://www.docker.com/products/docker-desktop/>, install it, start it,
  and wait until it says it is running. (On Windows, accept the "WSL 2"
  option if it is offered.)
- **Linux**: run `curl -fsSL https://get.docker.com | sh`, then
  `sudo usermod -aG docker $USER`, then log out and log back in.

Check that it worked: run `docker --version` and `docker compose version`.
Both should print version numbers. Keep Docker Desktop running while you use
the platform.

### 4.3 Download the project (clone)

Open a terminal **in the folder where you want the project to live** (on
Windows: open the folder, then open PowerShell or "Git Bash" there), and run:

```bash
git clone -b private https://github.com/Erfanmghs/recon-pipeline.git
cd recon-pipeline
```

Because the repository is **private**, GitHub asks you to prove who you are
during the download. Two easy ways:

- **Easiest -- GitHub CLI**: install it from <https://cli.github.com/>, run
  `gh auth login` once, then repeat the clone command. No passwords after
  that.
- **With a Personal Access Token**: on GitHub open Settings -> Developer
  settings -> Personal access tokens -> **Tokens (classic)**, generate a
  token with the `repo` and `read:packages` ticks, and when the clone asks
  for a password, paste that token (not your GitHub password). Keep the
  token handy -- step 4.5 option A reuses it.

> You can also download the code as a ZIP from the green **Code** button on
> the repository page -- but cloning with Git makes every future update a
> one-command job (see 4.8).

### 4.4 Create your settings file

Inside the `recon-pipeline` folder, run:

```bash
cp .env.example .env
```

(The same `cp` command works in PowerShell; in the old Windows command
prompt, use `copy` instead.)

Open the new `.env` file with any text editor and set one line -- the login
password for the dashboard:

```
DASHBOARD_TOKEN=changeme
```

Replace `changeme` with a long password of your choice. That is enough to
start. (If you want Telegram alerts, also paste the bot token here -- see
section 7. You can skip that for now and do it later.)

### 4.5 Start the platform

**Read this once:** the slow part (downloading or building the app's
package) happens **only on the first start of each machine**. Every start
after that takes **a few seconds**, and after a reboot the platform starts
itself -- you just open the browser.

**Option A -- the fast way, nothing is built (recommended).** The
ready-made app is downloaded from the platform's package store. It reuses
the token from step 4.3:

```bash
docker login ghcr.io -u YOUR-GITHUB-USERNAME   # paste the token as the password
docker pull ghcr.io/erfanmghs/recon-pipeline:dashboard
docker tag ghcr.io/erfanmghs/recon-pipeline:dashboard recon-pipeline-dashboard
docker compose --profile dashboard up -d
```

The download is one small app-sized package -- usually well under a minute.

**Option B -- build on your machine instead.** One command, no login. This
is the only slow step you will ever do (5-15 minutes on a slow internet),
and it too happens once:

```bash
docker compose --profile dashboard up -d --build
```

Both options end in the same place: the platform is running. Check it with
`docker compose ps` -- the status should say `Up`.

### 4.6 Open the dashboard

Open **http://127.0.0.1:8080** in your browser, paste the same password you
put in `DASHBOARD_TOKEN` into the box at the top-right, and you are in.

### 4.7 Prove that everything works

1. On **SETTINGS**, type your Telegram username and press **SEND TEST** --
   a test message should arrive (section 5, step 1).
2. On **TARGETS**, add the website you own.
3. On **RUN CONTROL**, press **START** and watch the check run live.

The complete walk-through is in section 5 and inside the dashboard's HELP
panel.

### 4.8 Everyday commands (cheat sheet)

| I want to ... | Command |
|---|---|
| Start it (everyday, a few seconds) | `docker compose --profile dashboard up -d` |
| Never type that again | Docker Desktop starts on login and the platform restarts itself -- after a reboot, just open the browser |
| Stop everything | `docker compose --profile dashboard down` |
| Update to the newest version | `git pull`, then `docker compose --profile dashboard up -d --build` |
| Watch what it is doing right now | `docker compose logs -f dashboard` |
| Check that it is running | `docker compose ps` |

### 4.9 If something goes wrong

| What you see | Why | What to do |
|---|---|---|
| `git: command not found` | Git is not installed, or the terminal was already open during install | Install it (4.1) and open a new terminal |
| `docker: command not found` | Docker is not installed, or Docker Desktop is not running | Install it (4.2) / start Docker Desktop and wait until it is running |
| `permission denied ... docker.sock` (Linux) | Your user is not in the docker group | `sudo usermod -aG docker $USER`, then log out and back in |
| Clone rejects my password | GitHub no longer accepts account passwords | Use a Personal Access Token or `gh auth login` (4.3) |
| Clone says `repository not found` | Your account has no access to this private repository, or the address has a typo | Ask the owner to invite your account and re-check the address |
| First start says `pull access denied` or `unauthorized` | The ready-made image needs your GitHub login, or the token lacks `read:packages` | Do the login from 4.5 option A, or run option B (`--build`) once |
| `port is already allocated` | Another program is using port 8080 | Add `DASHBOARD_BIND_PORT=9090` to `.env`, restart, and open http://127.0.0.1:9090 |
| The dashboard page does not open | It is still building, or it stopped | Run `docker compose ps`; wait until the status says `Up`, then reload the page |
| First start seems frozen | It is downloading, not frozen | Wait, or run `docker compose logs -f dashboard` to see the progress |

That is the whole installation. From now on, you only need the browser -- and
the cheat sheet above.

## 5. Using it day to day (the whole journey)

### Step 1 -- Tell it where to send alerts (one time)

Open the **SETTINGS** page. There is one box that asks for **your Telegram
username or numeric id**. Type `jackjohns` (or `@jackjohns`, or a number like
`123456789`) and save. That is the only thing you ever have to enter: no bot
creation, no chat setup, just your own handle.

Personal usernames deliver after you open your bot in Telegram and press
START once -- the platform learns your chat automatically. Public channel
handles (`@teamname`) work immediately.

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

- **You** set **only your Telegram username or numeric id**. Nothing else.
- The **bot token** -- the one-time key that lets the platform talk to
  Telegram -- is pasted into the `.env` file once by the person who installed
  the platform (section 7). Everyday users never see or touch it.
- **Backup tokens**: list extra tokens in `.env`, separated by commas. If a
  token stops working, the platform **rotates to the next one automatically**
  during the very same send -- no human needed.
- **Each website can override the default**: its own username, or "no alerts
  for this one". The website's own setting always wins over the global one.
- Press **SEND TEST** on the SETTINGS page and a test message should arrive
  within seconds. If it does not, the platform shows a human next-step hint
  instead of failing silently.

## 7. For the person who installs the platform (one-time, 5 minutes)

These lines go into the `.env` file:

| Line | What it is | Where to get it |
|---|---|---|
| `DASHBOARD_TOKEN` | The dashboard login password. | You choose it yourself. Make it long. |
| `TELEGRAM_BOT_TOKEN` | Lets the platform send Telegram messages. | In Telegram, talk to `@BotFather`, send `/newbot`, follow the two questions, and copy the long token it gives you. Extra tokens separated by commas act as automatic backups. |
| `PROXY_POOL` (optional) | Comma-separated proxies for IP rotation. | Your proxy provider. See the HELP panel / docs/HELP.md section 10. |

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
| [docs/HELP.md](docs/HELP.md) | Everyone | The complete step-by-step user guide, with examples -- also built into the dashboard's HELP panel. |
| [docs/HANDOVER.md](docs/HANDOVER.md) | Developers | The full engineering guide: architecture, every part explained, how to extend safely. |
| [docs/api-keys.md](docs/api-keys.md) | Users | Every optional key, where to get it, and what it unlocks. |
| [docs/security.md](docs/security.md) | Operators | How tokens and secrets are handled, and what to do if one leaks. |

## 13. Legal

Run only against targets you are authorized to test. Unauthorized scanning of
systems you do not own or do not have permission to test is illegal. The
platform's allow-list enforcement exists to protect you; do not fight it.
