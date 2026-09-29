# Show HN — portview

> Working notes for the launch post. This file is a draft for you to rewrite
> in your own voice, not something to paste verbatim. The notes at the bottom
> matter more than the text — read them before posting.

---

## Title options (pick one, ≤80 chars)

- `Show HN: I built a TUI that turns Windows Firewall into a keystroke`
- `Show HN: portview – see what's listening, allow or block it without the MMC snap-in`
- `Show HN: netstat that can actually change your firewall`

The second is best. It names both halves of what the tool does.

---

## Body

```
Windows Firewall is genuinely hostile to use.

To open a single port you launch "Windows Defender Firewall with Advanced
Security", click into Inbound Rules, create a new rule, pick TCP, type the
port, select "Allow the connection", invent a name, and click through the
rest of the wizard. And to find out whether you need to do that at all, you
open a different tool — netstat, or Task Manager, or Resource Monitor — and
go hunting for the PID.

So the workflow is: find the port in one tool, switch to another tool, click
through seven screens, fill in a form. Every time. Forever.

I wanted that to be two keystrokes in one place, so I built portview.

[SCREENSHOT / GIF HERE — see notes]

It runs a live TUI of every TCP and UDP socket mapped to its owning process,
with per-process CPU, RAM, and live bandwidth. Then, from that same list:

  F4   toggle the selected port's firewall rule between allowed and blocked
  F2   create a rule for the selected process, prefilled with its exe path

The F2 modal opens with the process name and application path already filled
in, because that information is already in the socket table and you would
otherwise have to go look it up. You type the port, hit enter, and the rule
is committed to the real Windows Firewall through the NetFwPolicy2 COM API.
Not a simulation — the actual policy.

It also surfaces firewall rules belonging to programs that aren't currently
running, marked IDLE, so you can finally see the stale rules you've
accumulated over the years.

Some specifics, since people always ask:

- Zero dependencies. Single ~300KB .exe, statically linked. No redistributable,
  no npcap or packet-capture driver. Just the standard Windows SDK.
- C++17, ~2900 lines, MIT. No framework, no event loop library.
- Runs unprivileged and degrades gracefully. The banner shows [ELEVATED] or
  [NOT ELEVATED] so you know what you're getting.
- --static emits a scriptable snapshot for piping into grep or a log.

What it does *not* do: IPv6 (AF_INET only for now), and no historical data —
it's a live view, not a time series.

I built this because I kept opening the same six screens for the same kind of
thing, and it annoyed me enough to write it. Curious whether other people hit
the same wall, or whether there's an established workflow I just never knew
about.

GitHub: https://github.com/mrun1corn/portview
```

---

## Posting notes

**1. The image is the post.** On Show HN, a post without a screenshot gets
scrolled past in under a second. Text cannot do this job. Record a 10–15
second clip: launch, type a port to filter, arrow to a row, press `F4`, show
the status badge flip. That sequence *is* the pitch.

```powershell
asciinema rec demo.cast portview.exe
# demo for ~12 seconds
asciinema svg demo.cast demo.svg
```

Windows Terminal also records via Settings → Open Console → Start recording.
This has to be a real capture of a real session — I can't produce it and
wouldn't fabricate output I never ran.

**2. Timing.** Tuesday or Wednesday, 9–11am ET. That's when the front page
actually happens.

**3. Be present for the first two hours.** The first hour decides whether it
trends. Someone will ask how this differs from bandwhich — the answer is
that bandwhich shows you traffic and is read-only, while this writes actual
firewall policy. Have that ready.

**4. Never ask for stars or upvotes.** Instant downvote trigger. It should
read as "here's a thing, here's why, here's the honest limitation."

**5. Be ready for the conversion-ratio question.** 1,277 views to 8 downloads
is the real weak spot and someone may notice. If pressed, say plainly that
the tool was young and this is the first serious distribution attempt. Don't
spin it.

**6. If the post body renders slowly, put the GIF in the first comment.**
Plenty of HN readers check comments before the body.

---

## After posting

- **Cross-post to r/commandline, r/windows, r/networking** — but rewrite the
  first line for each. Pasting identical text into three subreddits is how
  tools get flagged as spam.
- **Awesome-list PRs:** `awesome-command-line-apps`, `awesome-cpp`,
  `awesome-windows`, `awesome-network-tools`. Roughly 15 minutes each and
  permanent passive traffic. Do these regardless of how HN goes.
- **Re-measure after 48h** via `Insights → Traffic`. If views jumped but
  downloads didn't, the repo page still isn't converting — fix the page, not
  the post.
