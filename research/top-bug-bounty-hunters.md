# Top Bug Bounty Hunters: Comprehensive Research Report

**Compiled:** 2026-03-09
**Sources:** HackerOne blog, BugBountyForum AMAs, personal blogs, PortSwigger Daily Swig, Detectify Labs, Darknet Diaries, DefCamp interviews, Critical Thinking Bug Bounty Podcast, samcurry.net, blog.orange.tw

---

## Part 1: Platform Overview & Earnings Statistics

### HackerOne All-Time Figures (as of late 2024/early 2025)
- **$300M+ total** paid to researchers since platform launch
- **$81M paid in the last 12 months** (13% YoY growth)
- **30+ researchers** have crossed $1M lifetime earnings
- **1 researcher** has crossed $4M lifetime earnings (identity not publicly disclosed by HackerOne)
- **Top 100 all-time earners** collectively earned $31.8M
- **Top 10 programs** paid $21.6M (July 2024–June 2025)
- **2M+ registered researchers** on platform

### The Known Million-Dollar Club (HackerOne)
Publicly confirmed million-dollar earners, in rough chronological order of milestone:

| Handle | Real Name | Country | Notes |
|--------|-----------|---------|-------|
| @try_to_hack | Santiago Lopez | Argentina | First to $1M (March 2019, age 19) |
| @mlitchfield | Mark Litchfield | UK | First UK hacker to $1M |
| @fransrosen | Frans Rosen | Sweden | Co-founder of Detectify; #2 on HackRead list |
| @nnwakelam | Nathaniel Wakelam | Australia | $1.8M+ total; 8th all-time by reputation |
| @ngalog | Ron Chan | Hong Kong | $1M+ |
| @dawgyg | Tommy DeVoss | USA | $1M+; $160k in a single day (Oct 2018) |
| @inhibitor181 | Cosmin Iordache | Romania | First to $2M (2020) |
| @todayisnew | Eric Head | USA | #1 all-time by reputation (71,078 pts, 3,572 vulns) |

> Note: nahamsec (Ben Sadeghipour) has earned "nearly $2M" across career per public statements. The $4M all-time record holder has not been publicly named by HackerOne as of this research.

### HackerOne vs. Bugcrowd
- **HackerOne:** 2M+ researchers, JavaScript-gated leaderboard, nine distinct leaderboard categories
- **Bugcrowd:** ~500K researchers (per 2024 TechCrunch); top Bugcrowd hunter earned $1.2M+ in a single 12-month period (April 2024–April 2025); zseano reached #2 overall in 8 months
- **Intigriti:** Growing European platform, active leaderboards

### Countries (HackerOne, percentage of bounty value)
USA, India, and Russia collectively take 36% of total bounty value annually.

---

## Part 2: Hunter Profiles — Methodology, Specialties, Famous Findings

---

### 1. Cosmin Iordache (@inhibitor181)
**Country:** Romania (based in Germany)
**Platform:** HackerOne
**Earnings:** $2M+ (first ever; started 2017)
**Reputation:** Multiple-time invitee to HackerOne live hacking events

**Background:** Full-stack developer who attended the HackAttack seminar in Hamburg in 2017 and pivoted to bug bounty hunting.

**Specialty:** Cloud and SaaS misconfiguration; custom narrow-scope tooling.

**Methodology:**
- **Deep single-program focus.** After "trying to attack everything in the beginning and having bad results," he shifted to spending extended time on one program at a time.
- **Custom tooling with extremely specific jobs** rather than broad automation suites.
- **Program selection:** Chooses based on payout ranges and scope quality. "Higher payouts attract better hackers, which raises the bar even more."
- **Cloud misconfigurations** as a starting point: "Complex services that are very customizable and come with lots of documentation" create configuration gaps.
- **Disengages immediately** from programs that show disrespect or payment delays.

**Key Quotes:**
- "Bug bounty is not something you learn in a few months—it has an extremely steep learning curve, so be prepared to invest much time."
- "The main motivator for me is the money I earn."
- "Invest time in something specific" — whether attack techniques, documentation study, or research.

**Learning Resources:** Twitter, HackerOne Hacktivity, PentesterLab.

---

### 2. Eric Head (@todayisnew)
**Country:** USA
**Platform:** HackerOne
**Rank:** #1 all-time by reputation (71,078 reputation points, 3,572+ vulnerabilities)
**Thanks from:** Adobe, Verizon Media, PayPal, and 137 others

**Background:** Username "todayisnew" came from a difficult period in 2004 following a legal situation with Yahoo — he created it as a personal mantra that "each day is new."

**Methodology:**
- **99% automated** research. "My research methods are 99% automated so the more programs I engage in, the more bugs I find."
- Engages multiple programs simultaneously, using automation to cast a wide net.
- Submits **highest-impact vulnerabilities first** on higher-paying programs, managing time as primary constraint.

**Key Quotes:**
- "Companies and hackers should view themselves as on the same side."
- Sign-off: "may you be well on your side of the screen."

---

### 3. Santiago Lopez (@try_to_hack)
**Country:** Argentina
**Platform:** HackerOne
**Earnings:** $1M+ (first ever, age 19, March 2019); 1,600+ vulnerabilities reported
**Programs:** Twitter, Verizon Media

**Background:** Self-taught via online tutorials and the movie "Hackers." Joined HackerOne in 2015 at age 16, earned first $50 for a CSRF.

**Specialty:** IDOR (Insecure Direct Object Reference) — quantity-focused approach.

**Methodology:**
- **Quantity over quality** — directly contradicts conventional wisdom. "I know they say quality before quantity, but quantity is what I like."
- **IDOR specialization:** "It is a vulnerability that is very easy for me to find and larger bug bounty programs often pay well for them."
- Hacks 6–7 hours per day, preferring evening/nighttime sessions.
- Largest single bounty: $9K for an SSRF in a private program.
- **Pragmatic program selection:** "I care less about whether they are private or public, and care more about the scope."

**Quote:** "I am incredibly proud to see that my work is recognized and valued. Not because of the money, but because this achievement represents the information of companies and people being more secure."

---

### 4. Tommy DeVoss (@dawgyg)
**Country:** USA
**Platform:** HackerOne
**Earnings:** $1M+ (reached milestone 2019); former all-time rank #20
**Recognition:** Verizon Media Most Valuable Hacker

**Background:** Started hacking at age 9–10 on EfNet IRC. Arrested in high school for breaking into government systems, served 4 years in prison. Discovered bug bounties in 2016 as a legal outlet. Between 2016–2019 earned ~$910,000.

**Record:** October 2018 — **$160,000 in one day** by finding 16 SSRF vulnerabilities on Nexus RF endpoints at Verizon Media. Each vulnerability paid $10,000. He had found a blacklist bypass that worked across 15–16 separate endpoints.

**Specialty:** SSRF, RCE.

**Methodology:**
- **Manual-first, minimal automation.** Uses Aquatone, Sublist3r, and Altdns for discovery, then "hunts old-school" with Burp Repeater for everything else.
- **Focus on 1–2 programs simultaneously** to learn applications deeply.
- **Initial test:** Starts with lower-severity bugs to assess company response times and trustworthiness before investing in higher-effort research.
- **Engagement trigger:** Quick payment cycles and fair triage.
- **Disengagement trigger:** Slow turnaround, questionable duplicate marking.

**Key Quotes:**
- "The amount of money that you can make doing this legally far outweighs the money you're gonna make illegally."
- "Money is my main and biggest motivator." But also: "our time is valuable" — he respects mutual professional conduct.

---

### 5. Nathaniel Wakelam (@nnwakelam / "Naffy")
**Country:** Australia
**Platform:** HackerOne
**Earnings:** $1.8M+ total; earned $60K+ in first university semester
**Rank:** 8th all-time by reputation (7,000+ pts, 343+ vulns)

**Background:** Got hooked on bug bounties as a teenager while playing an MMO. CISO at Gravity.net.

**Methodology:**
- **Low-hanging fruit first** when evaluating a program. "Bug bounties are a time investment and if you aren't getting a return on that, reassess your strategy."
- **Minimal toolkit:** Terminal, internet connection, and black shades.
- **Collaborative rivalry:** Fierce competition with "notnaffy" forced both to "adapt and grow in new and interesting ways to actually find bugs the other one wouldn't find."
- **Unconventional hours** — noted writing at 5 AM Friday mornings.
- Co-created **Altdns** (subdomain permutation/resolution) and **Assetnote** monitoring tools with Shubham Shah.

**Key Quote:** "Don't be a stranger… treat people with respect and be open and honest with your communications."

---

### 6. Ben Sadeghipour (@nahamsec)
**Country:** USA (California)
**Platform:** HackerOne, Bugcrowd
**Earnings:** ~$2M lifetime; ~$500K/year as of 2024
**Notable:** $100K bounty from Meta (first and only Meta submission, chased for a decade)

**Background:** Introduced to bug bounty by a friend in 2016. Previously a software engineer. Now also a content creator, runs nahamsec.com, created labs platform with 100+ real-world scenario labs.

**Specialty:** SSRF, IDOR, mobile recon.

**Methodology:**
- **Application understanding first:** Uses the app as a regular user before testing — maps functionality, file upload points, external fetch points, account data flows.
- **Recon approach:** Subdomain enumeration looking for internal naming patterns (domain.dev.target.com, domain.corp.target.com); Shodan/Censys for broad asset discovery; GitHub dorking for API endpoints, internal apps, subdomains.
- **Mental checklist over scattershot testing:** "In the very beginning I had a hard time finding bugs because I didn't have a methodology/routine — I was all over the place."
- **SSRF hunting:** Tests localhost/127.0.0.1, port scanning, protocol variations.
- **IDOR:** Systematically modifies numerical IDs in API calls, uses Burp Intruder for response analysis.
- **Mobile recon:** Extracts endpoints absent in web versions, finds hardcoded third-party keys.
- Reports 15–20 vulnerabilities per month, 15–30 hours/week.

**Key Quotes:**
- "The first bug is always the hardest, but once you find that first one, everything becomes a bit easier."
- "Understand how applications work instead of jumping in and copy/pasting payloads."
- "Something that may be obvious to one person, may not be as obvious to another. So always approach a target without considering other hackers that have already looked at the program."

---

### 7. Orange Tsai (real name: Cheng-Da Tsai)
**Country:** Taiwan
**Affiliation:** Principal Security Researcher at DEVCORE; CHROOT Security Group
**Platform:** Bug bounty + full vulnerability research
**Recognition:** Pwn2Own champion 2021 and 2022; Pwnie Award winner 2019 and 2021; PortSwigger Top 10 Web Hacking Techniques multiple times; Phrack #72 author (2025)

**Self-description:** "RCE enthusiast."

**Major Findings:**
- **ProxyLogon (CVE-2021-26855):** Chained SSRF + privilege escalation + arbitrary file write = pre-auth RCE on Microsoft Exchange. Affected hundreds of thousands of servers globally.
- **ProxyShell:** Additional Exchange pre-auth RCE chain, demonstrated at Pwn2Own 2021.
- **Pulse Secure SSL VPN:** 7 vulnerabilities affecting Twitter, Uber, Tesla.
- **GitHub Enterprise:** 4-vulnerability chain from blind SSRF to unsafe deserialization = RCE.
- **Apache Confusion Attacks (2024):** 3 attack categories, 9 new vulnerabilities, 20 exploitation techniques, 30+ case studies including root access via `?` character bypassing ACLs.
- **CVE-2024-4577:** PHP RCE.
- **Facebook MobileIron MDM:** Unauthenticated RCE.

**Methodology — The Core Approach:**

Orange's defining characteristic is **architectural analysis rather than individual bug hunting**. He asks: "Could I use a single HTTP request to access different contexts in Frontend and Backend to cause confusion?" His research repeatedly returns to the theme of inconsistencies between system components.

For ProxyLogon:
- Targeted the Client Access Service (CAS) proxy layer — "if the entrance of Exchange is 0, and 100 is the core business logic, ProxyLogon is somewhere around 10."
- Identified that different modules maintained different header blacklists — inconsistency exploitable for privilege escalation.
- Combined: SSRF (auth bypass) + internal API abuse (privilege escalation) + arbitrary file-write (RCE).

For Apache Confusion Attacks:
- Noticed "modules do not fully understand each other, yet they are required to cooperate."
- **Filename Confusion:** Some modules treat `r->filename` as filesystem path, others as URL — exploitable inconsistency.
- **DocumentRoot Confusion:** Modules access both paths with and without document root.
- **Handler Confusion:** Legacy 1996 code converting `content_type` to handler interchangeably.
- Methodology: code archaeology tracing 28-year-old functions, GitHub mining for vulnerable configurations, systematic gadget hunting in `/usr/share`.

**Core Mental Model:** "Architectural issues often yield more vulnerabilities than isolated bugs." He deliberately investigates **technical debt** and **legacy compatibility obligations** as vulnerability sources.

---

### 8. Frans Rosen (@fransrosen)
**Country:** Sweden
**Affiliation:** Co-founder and Knowledge Advisor at Detectify
**Platform:** HackerOne
**Earnings:** $1M+
**Rank:** #2 on HackRead's Famous Bug Bounty Hunters list

**Specialty:** OAuth security, postMessage vulnerabilities, subdomain takeovers, S3 bucket exposure.

**Famous Findings:**
- **"Dirty Dancing" in OAuth Flows:** Systematically tested 125+ websites running bug bounties, documenting OAuth flows. Discovered three "gadget" categories for stealing tokens without traditional XSS: (1) weak postMessage listeners lacking origin checks that expose `location.href`; (2) XSS on sandboxed third-party domains + iframe manipulation + window.name exploitation; (3) APIs/storage that leak user URLs out-of-bounds.
- **Slack Token Theft (2017):** Found Slack passed messages to a window-object listener without validating origin. Created malicious page that reconnected Slack's WebSocket to attacker-controlled WebSocket to steal XOXS tokens. Fixed in <5 hours; paid $3,000.
- **S3 Bucket Subdomain Takeover (2014):** Early research establishing subdomain takeover attack patterns.
- **Apple CloudKit:** Three bugs in iCrowd+, Apple News, Apple Shortcuts.

**Methodology:**
- **Automated reconnaissance:** Combines SubBrute, Altdns, Massdns, bash scripts. "Asset discovery is a key to success."
- **Testing flow:** (1) Surface XSS/input validation; (2) proxy all traffic marking abnormal responses; (3) JavaScript analysis for suspicious data handling; (4) minified code review for endpoint discovery.
- **Finding SQLi/RCE:** During input validation testing using template engine strings as payloads.
- **Program timing:** Identifies three phases — launch chaos (dupes), middle period, and 6–18 month mark ("best opportunity due to new code").
- **Developer's mindset:** "If you are a developer, try think of times when you thought 'Oh shit, I did this wrong'" — use personal coding mistakes as vulnerability templates.

**Key Quotes:**
- "How can this actually get exploited?" — fundamental question driving his research.
- "Keep digging. Really. You will have times where you just want to quit."
- "I read A LOT. The interesting thing here is that you can never read too much."

---

### 9. Sam Curry (@samwcyo / HackerOne: @zlz)
**Country:** USA (Omaha, Nebraska; born 1999)
**Platform:** HackerOne, Bugcrowd
**Earnings:** $500K by age 18; founded Palisade Security consulting group at 18
**Collaborators:** Brett Buerhaus, Ben Sadeghipour, Shubham Shah, Ian Carroll, Brett Buerhaus, Neiko Rivera

**Major Research:**
- **Hacking Apple for 3 Months (2020):** With Brett Buerhaus, Samuel Erb, Tanner Barnes, Ben Sadeghipour. 55 vulnerabilities total: 11 critical (RCE, auth bypass, wormable XSS), 29 high (SSRF, SQLi, XXE). $288,500 paid.
- **Web Hackers vs. The Auto Industry (2022):** 16 car manufacturers. Vulnerabilities in BMW, Rolls Royce, Mercedes-Benz, Ferrari, Spireon, Hyundai/Genesis, Ford, Reviver. Spireon SQL injection provided command access to 15.5M vehicles including police fleets.
- **Subaru STARLINK (2025):** Remote control of Subaru vehicles — lock/unlock, engine start/stop, track location — using only a license plate number.
- **Kia (2024):** Remotely control any Kia via license plate only; also access the vehicle's 360-degree camera live.
- **TSA Airport Security (2024):** With a colleague, revealed a weakness allowing bypass of TSA airport security screenings.
- **Tesla:** XSS via referrer header containing VIN number firing on internal dashboard.

**Methodology:**
- **Reconnaissance-first:** OSINT tools (gau, ffuf), JavaScript reverse-engineering to identify API endpoints and constants before testing.
- **Pattern recognition:** Identified recurring SSO failure pattern — poorly implemented single sign-on failing to restrict underlying application access — appearing across multiple manufacturers.
- **Escalation testing:** Never stops at initial access; demonstrates downstream system impact (dealer portals, internal tools, production APIs).
- **Deep single-program focus:** "I love digging deep and am unable to focus if I'm trying to find vulnerabilities on multiple targets at once."
- **Collaboration:** Deliberately assembles teams with diverse expertise.

**Key Quotes:**
- "Working with others is one of the best ways to grow."
- "The time it takes for a submission to receive a bounty is as important as the actual bounty amount."
- On motivation: "A lot of the hacking he does is based around fun and curiosity now instead of bug bounties."

---

### 10. Brett Buerhaus (@bbuerhaus)
**Country:** USA
**Platform:** HackerOne, Bugcrowd (ranked #16 on Bugcrowd)

**Major Findings:**
- **Apple (with Sam Curry team):** Escalated XSS in PhantomJS image rendering → SSRF → Local File Read → full AWS secret keys for EC2 and IAM role.
- **US Air Force:** With Mathias Karlsson, found a flaw in Air Force public website allowing access to the DoD's unclassified internal network. Paid $10,650 — largest government bug bounty reward at the time.

**Methodology (6 steps):**
1. Review scope
2. Perform reconnaissance (Google, Shodan, Censys, ARIN for subdomains/endpoints)
3. nmap port and banner scanning ("I start to perform nmap port and banner scanning to see what type of servers are running")
4. Review services/applications — manually browse, review JavaScript for AJAX calls, examine Flash media
5. Custom fuzzing — builds personalized scripts and wordlists rather than relying on Burp/SQLmap
6. Build proof-of-concept from discovered vulnerabilities

**Infrastructure focus:** Prioritizes finding critical applications like RabbitMQ or Jenkins. Assesses WAF presence, CSRF protection, input filtering vs. encoding.

---

### 11. Tom Hudson (@tomnomnom)
**Country:** UK
**Affiliation:** Security researcher at Detectify
**Platform:** HackerOne, Bugcrowd

**Known for:** Building the tool ecosystem that much of the bug bounty world uses.

**Tools Created:**
- **waybackurls** — fetches all URLs the Wayback Machine knows about for a domain; uncovers deprecated endpoints still active in backends
- **assetfinder** — discovers subdomains from multiple passive sources
- **httprobe** — checks a list of domains for listening HTTP servers
- **gf** — grep pattern system using JSON-defined aliases
- **meg** — fetches many paths for many hosts without hammering servers
- **qsreplace** — replaces values in URL query strings

**Methodology:**
- Background as a Software Engineer led him to automate his own bug bounty process.
- **Tool-building as research:** He identifies problems in his own hunting workflow and builds tools to solve them.
- **"The real skill comes from knowing how and when to use each tool and chaining them together."**
- Believes the highest-impact vulnerabilities appear when slowing down and thinking creatively — not from automation alone.
- **Bash-first philosophy:** His "Bug Bounties With Bash" talk demonstrates building recon pipelines from basic Unix tools.

---

### 12. Ron Chan (@ngalog / GitHub: @ngalongc)
**Country:** Hong Kong
**Platform:** HackerOne
**Earnings:** $1M+

**Background:** Started hacking April 2016 after the OSCP course. Discovered bug bounty through Orange Tsai's Facebook SQLi to RCE blog post. First bug: purchasing anything at any price on Yahoo Pay.

**Breakthrough:** Reading zseano's tutorial on leveraging open redirects to Facebook linked account takeover. "I was struck by the concept of increasing the impact even for a trivial bug" — applied this to OAuth, found multiple OAuth bugs at Uber and ATO bugs at Flickr, earning ~$40K from this insight alone.

**"1k Per Day Challenge":** Earned $31,000 across 30 days through deep engagement with fewer targets.

**Specialty:** OAuth/SSO implementation weaknesses, account takeover, SSRF, postMessage XSS, open redirect chaining.

**Methodology:**
- **No automation whatsoever.** "All I have is a Burp Pro license." Strategy relies on manual traffic analysis and pattern recognition.
- **Deep protocol understanding:** URL parsing inconsistencies, redirect behavior across browsers, cookie handling, OAuth state parameter misuse.
- **Chaining minor issues:** His most successful exploits combine multiple "minor" vulnerabilities into high-impact attacks. Example: login CSRF + open redirect + token exposure = account takeover.
- **Signature patterns:**
  1. OAuth State Parameter Abuse (using CSRF-protection state as open redirect vector)
  2. URL encoding tricks (double-encoding, mixed encoding, path traversal for validation bypass)
  3. Cross-domain session leakage (inconsistent URL decoding across related domains)
  4. Referer header information disclosure via redirect chains
- **Target focus:** Platforms with OAuth implementations and microservices (Uber, Flickr, Yahoo, Google).

**Key Quote:** "Keep reading the write-ups and replicate it in your local environment when you don't understand it."

Also maintains [bug-bounty-reference](https://gitlab.com/ngalongc/bug-bounty-reference) — a categorized list of community writeups.

---

### 13. Jack Cable (@jackhcable)
**Country:** USA
**Platform:** HackerOne (top 100 all-time)
**Recognition:** Time Magazine 25 Most Influential Teens 2018; Stanford CS
**Current role:** Senior Technical Advisor at CISA

**Background:** Began hacking in high school; placed first in Hack the Air Force challenge. After discovering vulnerabilities in electoral infrastructure, joined CISA in summer 2020. Rejoined in 2023 to lead CISA's Secure by Design initiative.

**Scope:** 350+ vulnerabilities at Google, Facebook, Uber, Yahoo, DoD. Developed Crossfeed — passive vulnerability scanning across all 50 states and 2,500+ counties election infrastructure.

**Methodology:**
- **Medium-sized site focus:** "I've had the most success with medium-sized sites, where I try to comprehensively understand every feature of the site."
- **Improved recon process** over time; uses Jason Haddix's domain tool for subdomain discovery, then probes which subdomains respond.
- **Systematic:** "There are days when it's difficult to find vulnerabilities and days when bugs come easily — it's important to keep trying to approach targets in different ways and switch targets once in a while."
- Focus has shifted toward **systemic improvement** — open source security legislation, Secure by Design principles — over individual bug hunting.

---

### 14. Corben Leo (@hacker_)
**Country:** USA
**Platform:** HackerOne, Bugcrowd (legendary DoD hunter)

**Known for:** SSRF expertise, recon tooling, the tool **GAU** (GetAllUrls).

**Tools:** GAU (collects URLs from multiple sources: Wayback, Common Crawl, URLScan).

**Notable writeup:** "Hacking the Hackers: Leveraging an SSRF in HackerTarget" — used an SSRF in HackerTarget's own infrastructure to access their internal services.

**Methodology:**
- **Feature-based SSRF discovery:** Rather than parameter spraying, identifies application features that inherently make server-side requests (webhooks, URL fetchers, PDF generators, image importers).
- **Application architecture intelligence:** Maps the backend architecture to understand what internal services exist before attempting SSRF.
- Comprehensive automation combined with targeted manual verification.

---

### 15. zseano (Sean)
**Platform:** Bugcrowd (#2 overall in 8 months)
**Created:** BugBountyHunter.com; 1,000+ vulnerabilities discovered

**Background:** Programming + hacking background; was playing Halo 2 and saw users cheating/modding, wanted to know how.

**Methodology Framework (from his paid guide):**
- **Depth over breadth:** "Rather than jumping from program to program, focusing on one program and learning as much as you can about their scope and features will usually result in more bugs being discovered."
- **Checklist-driven:** Designed as easy-to-follow flow/checklist for web application vulnerabilities.
- **Impact escalation emphasis:** His tutorial on leveraging open redirects to full account takeover was cited by both Ron Chan and Nathaniel Wakelam as transformative insights for their own careers.
- Known for publishing accessible, step-by-step vulnerability chains that demonstrate how trivial bugs become critical.

---

### 16. STÖK (Fredrik Alexandersson)
**Country:** Sweden
**Platform:** HackerOne
**Recognitions:** Uber, Salesforce, Microsoft, DoD, HackerOne, Dell
**Background:** 25 years IT industry experience; Active Directory specialist turned offensive researcher (2014+)

**Methodology:**
- **One host at a time:** "I approach each new target one host at a time. Gracefully, I do my recon, enumerate the hosts, do my content discovery, map out the terrain, study the app, read the docs."
- **Design-flow analysis, not code expertise:** "I don't understand most code, so I have to rely on deep understanding of design flows and figuring out what the developers missed."
- **Collaborative recon:** Advocates shared reconnaissance, believing teams covering problems from multiple angles find "really cosmic bugs" more effectively.
- **Structured work cycles:** 4–5 hour focused blocks; 8 hours sleep; no all-nighters.

**Famous Finding:** Active Directory SSO bypass using `./username` syntax instead of standard format in a Windows environment, gaining access to a test account created during installation — invisible to defenders in both AD and the application's user database.

**Quote:** "In security you can go as deep or as wide as you want."

---

### 17. Jason Haddix (@jhaddix)
**Platform:** Bugcrowd (#1 overall); also HackerOne
**Current:** CEO of Arcanum Security; former CISO at Budweiser's parent company
**Known for:** "The Bug Hunter's Methodology" — the de facto standard framework, updated yearly

**The Bug Hunter's Methodology Framework (jhaddix/tbhm):**
- **Phase 1:** Reconnaissance & Discovery (subdomain enumeration, port scanning, content discovery)
- **Phase 2:** Application Analysis
  - Mapping (architecture, endpoints)
  - Authorization & Sessions
  - Tactical Fuzzing (XSS, SQLi, File Inclusion, CSRF)
  - Privilege, Transport & Logic testing
  - Mobile vulnerabilities
  - Web Services / API testing
- **Phase 3:** Exploitation & Reporting

**Key Insight:** Manual recon tasks rather than pure automation. "Spending time to manually understand the target and 'eyeball' naming conventions gives a deeper understanding and edge on grabbing context and targets which automation could miss."

**DEF CON 32 Talk:** "The Darkest Side of Bug Bounty" — addressed systemic problems in bug bounty programs from his unique perspective as a hacker, program owner, and platform operator.

---

### 18. Arne Swinnen (@arneswinnen)
**Country:** Belgium
**Affiliation:** NVISO security consultancy

**Famous Research:** "The Tales of a Bug Bounty Hunter: 10 Interesting Vulnerabilities in Instagram" (2016)

**Key Findings (Instagram via Facebook Bug Bounty):**
- Android app blocked incorrect password guesses after 1,000 attempts but then allowed them on every other attempt after the 2,000th.
- Registration page: No rate limiting, allowed enumeration of whether credentials belonged to active accounts.
- IDOR + missing authentication combined to allow takeover of locked Instagram accounts. Estimated ~20M accounts (4% of ~500M) were vulnerable.

**Methodology:**
- **Multiple sweeps:** First sweep maps all functionality and tests for common bugs. Second and third sweeps target complex bugs ("I already knew the application's base functionality and technologies from the previous sweeps, allowing me to recognize exotic behaviour more easily").
- **Hybrid vulnerability focus:** Combines complementary issues across web and mobile platforms.
- **Advanced mobile techniques:** Binary modification, dynamic hooking, custom Burp Suite plugin development.
- **Root cause focus:** Maps vulnerabilities back to SDLC phase where they originated.
- **High selectivity:** "I'm allergic to informative and N/A, so I only report issues of which I'm 99% sure the company will appreciate."
- Reports 15–20 bugs monthly; 40–50 hours weekly during active periods (~10–12 months/year).

**Key Quote:** "Persist. There's always something that has been overlooked." / "Everyone has a different angle to approach a target, no individual hacker is perfect."

---

### 19. Shubham Shah (@infosec_au)
**Country:** Australia (Sydney)
**Affiliation:** Co-founder and CTO of Assetnote
**Platform:** HackerOne (top 50, #1 Australia)

**Background:** First bug bounty at age 14 from PayPal ($1,500). Bypassed 2FA at Google, Facebook, Yahoo, LinkedIn at age 16.

**Tools Created (with Nathaniel Wakelam):**
- **Altdns** — subdomain permutation/resolution
- **Assetnote** — continuous attack surface monitoring platform
- **Bugbounty Dash** — terminal dashboard for tracking efforts

**"High Frequency Bug Hunting" Experiment (120 days, 120 bugs):**
- Earned ~$80,000 in 120 days while working full-time.
- Core methodology: **asset discovery and monitoring** — everything virtually owned by a company including SaaS platforms.
- "Finding development boxes owned by a company, where a developer had only put the box or application online one hour before I had found it became quite lucrative."

**Key Insights:**
- "When I had dry periods... one of my colleagues would find something spectacular" — collaboration as resilience mechanism.
- Biggest mistake: "Not understanding bug discovery volatility" — three severe burnouts in 120 days.
- "When you submit bugs, remember that you aren't actually entitled to anything."

---

### 20. Patrik Fehrenbach (@ITSecurityguard)
**Country:** Germany
**Platform:** HackerOne (Certified), Bugcrowd (Verified), Intigriti (Verified)
**In the field since:** 2012
**Founding Member:** Bug Bounty Forum

**Specialty:** IoT, mobile, web applications; nmap-heavy infrastructure recon.

**Methodology:**
- **Infrastructure-first:** Open IP databases (RIPE, ARIN, APNIC) → nmap scan → port/banner analysis.
- **Application approach:** "I open up my notepad and try to collect as many information as I can find." Focuses parameters suggesting DB interaction (id=, user=) for SQLi; reflection points for XSS.
- **Tools:** Burp with extensions (Backslash Powered Scanner, Java Deserialization Scanner, SAML tools), needle (iOS), recon-ng, wpscan.
- **Patience over speed:** "It took about a year to step up from low quality bugs... once you gain experience, read a lot, and understand the techniques companies are using, finding good bugs becomes a matter of time."

**Quote:** "Don't hunt just for money, hunt for knowledge, hunt for fun."

---

### 21. filedescriptor
**Country:** Hong Kong
**Platform:** HackerOne (top percentile, invited to all global live hacking events)
**Collaborators:** @ngalongc (Ron Chan), @EdOverflow

**Specialty:** Business logic, authentication, access control, XSS — prioritizes simple bugs with huge impact.

**Famous Findings:**
- **Shopify Session Fixation (via XSS chain):** Found XSS, but since XSS was out of scope, kept exploring. Noticed session IDs didn't change after login (session fixation). Used the XSS to exploit session fixation.
- VPN extension IP and DNS leak research.

**Methodology:**
- **Deep single-program focus:** "You most often just need to change one parameter and it's already a critical bug."
- Targets "features at the application level with business logic issues."
- **Simple + High Impact mindset:** Does not chase exotic vulnerability classes; focuses on finding trivial bugs with overlooked critical impact.
- **Community:** Shares research via blog, videos; runs YouTube channel with ngalongc and EdOverflow.
- **Tool created:** untrusted-types (security testing tool).

**Key Quote:** "Learning new stuff makes me giggle."

---

### 22. Mathias Karlsson (@avlidienbrunn)
**Country:** Sweden
**Affiliation:** Former work at Detectify; now at Kivra

**Famous Findings:**
- **GitHub OAuth redirect bypass:** Discovered GitHub failed to properly validate redirect URLs during OAuth authorization, allowing attackers to redirect victims and steal OAuth tokens.
- **postMessage XSS on a Million Sites:** Research (published via Detectify Labs) demonstrating postMessage XSS affecting enormous numbers of websites.
- **US Air Force (with Brett Buerhaus):** Found flaw giving access to DoD internal network; paid $10,650.
- **CVE-2015-3755:** Same-origin policy bypass.

**Focus:** Web security, browser security, postMessage vulnerabilities, URL validation flaws.

---

### 23. Sergey Toshin (@bagipro)
**Country:** Russia
**Platform:** HackerOne (#1 on Google Play Security Reward Program)
**Created:** Oversecured (Android vulnerability scanning platform)

**Specialty:** Android mobile security.

**Methodology — Fully Automated:**
- **Downloads hundreds of apps** from multiple programs and scans them with Oversecured.
- **Targets non-obfuscated Android apps** ("much easier to understand what's going on in a particular source").
- When automated scans miss vulnerabilities in feature-rich apps, manually investigates to refine scanning technology.
- Vulnerabilities found include: arbitrary code execution, theft of arbitrary files, cross-site scripting.
- Continuous learning via Android Security Bulletins and Telegram security channels.

**Key Insight:** Systematic, technology-assisted vulnerability discovery outperforms traditional penetration testing in mobile security contexts.

---

### 24. Justin Gardner (@rhynorater)
**Country:** USA (Richmond, Virginia)
**Platform:** HackerOne (top 35 all-time; 450+ vulns; 2x Most Valuable Hacker)
**Also:** Co-host of "Critical Thinking - Bug Bounty Podcast" with Joseph Thacker (@rez0) and Brandyn Murtagh (@gr3pme)

**Background:** Penetration tester at SynerComm → IT Architect at Veivos → full-time bug bounty hunter (March 2020). OSCP (2018). DEFCON 2022 main stage presenter.

**Specialty:** SSRF, open source application vulnerabilities, hardware/IoT.

**Famous Finding:** Grafana SSRF (CVE-2020-13379) — chained redirects + URL parameter injection = full-read unauthenticated SSRF on Grafana 3.0.1–7.0.1. Made $100K+ on SSRF vulnerabilities.

**Methodology:**
- **Unauthenticated routes first**, then authentication bypasses.
- For open source applications: "spend more time on it than in black box assessments" once you find interesting functionality.
- SSRF: "They aren't always as simple as pointing at localhost or AWS Metadata service" — chains redirects, parameter injection, protocol tricks.
- Mentors aspiring hunters: "I will gladly share with you what knowledge I have if you prove to me that you are willing to work for it."

---

### 25. Yassine Aboukir (@yassineaboukir)
**Country:** Morocco
**Platform:** HackerOne (rank 11 all-time; 642+ vulnerabilities; 120+ organizations including Google, Yahoo, Twitter, Uber)

**Methodology:**
- **One program at a time.** Develops deep familiarity with assets, threat models, and builds relationships with security teams.
- **Functionality-driven testing** rather than vulnerability-type-driven: "For example, testing webhook APIs for SSRF vulnerabilities."
- **Manual over automated.** "Get your hands dirty every time you hack on a program."
- **Program selection criteria:** Bounty amounts, open scope, time-to-bounty, time-to-triage, and whether the program is actively maintained.
- **Disengages** from unresponsive teams or programs with poor vulnerability management.

**Quote:** "Patience and persistence" — primary advice for aspiring hunters.

---

### 26. James Kettle (PortSwigger Research)
**Affiliation:** Director of Research at PortSwigger
**Not a traditional bug bounty hunter** — primarily independent research published through PortSwigger, tooling for the community

**Major Research Areas:**
- **HTTP Desync / Request Smuggling** (2019): Brought request smuggling back from obscurity. Developed methodology, detection tooling (HTTP Request Smuggler Burp extension), and a systematic pipeline for scanning bug bounty programs.
- **HTTP/2 Request Smuggling** ("HTTP/2: The Sequel is Always Worse")
- **Web Cache Poisoning** — reframed from theoretical to practically exploitable
- **Server-Side Template Injection** (foundational research)
- **CORS misconfigurations**, timing attacks, race conditions
- **Backslash Powered Scanner** — automates intuition-driven testing rather than predefined patterns

**Methodology:**
- Chooses research directions by identifying **gaps in existing knowledge** — underexplored intersection points.
- **Human-centered automation:** "Backslash Powered Scanner concept encapsulates his philosophy — automating intuition-driven testing rather than predefined patterns."
- **Iterative deepening** within single topics (three generations of desync research across different protocol versions).
- Influences: lcamtuf, filedescriptor, homakov.

---

### 27. Jobert Abma (@jobert)
**Country:** Netherlands
**Co-founder:** HackerOne (2012)

**The "Hack 100" Initiative (2011):** With Michiel Prins, attempted to find security vulnerabilities in 100 prominent high-tech companies and found flaws in all of them — Google, Facebook, Apple, Microsoft, Twitter. This led directly to founding HackerOne with Alex Rice and Merijn Terheggen.

**Research style:** Early HackerOne blog posts on GraphQL security, SSRF, blind XSS, XXE (maintains tooling repos on GitHub for debugging these classes). Known as a technical generalist with deep platform-level thinking.

---

## Part 3: XBOW — The AI Entrant

**XBOW** is an autonomous penetration testing platform that reached the **#1 spot on HackerOne's US leaderboard** in July 2025 — the first AI system to do so.

**How it works:**
1. **Targeting:** Parses machine-readable bug bounty scopes; scores programs using WAF presence, authentication forms, endpoint counts, underlying technologies; uses SimHash for content similarity and image hashing to avoid duplicate scanning.
2. **Discovery:** Runs automated vulnerability detection across the full range: RCE, SQLi, XXE, Path Traversal, SSRF, XSS, cache poisoning, secret exposure.
3. **Validation:** "Validators" layer — automated checkers (sometimes LLM-based, sometimes custom scripts) verify whether a vulnerability truly exists before submission. XSS findings verified via headless browser.
4. **Human review:** Security team reviews findings pre-submission for policy compliance.

**Stats:**
- ~1,060 vulnerability submissions
- 130 resolved, 303 triaged
- 54 critical, 242 high in last 90 days
- Also found a previously unknown vulnerability in Palo Alto GlobalProtect VPN affecting 2,000+ hosts.

**Significance:** XBOW's success is in quantity at medium severity. Human top hunters still dominate at the highest-impact, highest-complexity findings that require contextual understanding and creative chaining. The consensus is: "not yet the end of human-led bug hunting."

---

## Part 4: Key Mental Models That Recur Across Top Hunters

### 1. Program Depth Over Breadth
Nearly every top hunter emphasizes focusing on 1–2 programs deeply rather than spraying across many. This applies from Tommy DeVoss (1–2 programs simultaneously) to Ron Chan (lazy — "test whatever is presented to me" within a chosen target) to Sam Curry ("I love digging deep and am unable to focus on multiple targets at once") to inhibitor181's "one program at a time" pivot that broke his plateau.

**Why:** Deep familiarity allows recognition of subtle anomalies that casual testers miss. You begin to understand what the developers were trying to build — and where they failed.

### 2. Impact Escalation / Vulnerability Chaining
The single most repeated concept: take a "trivial" or "low severity" finding and chain it to something critical.
- Ron Chan's career turned on learning from zseano that an open redirect could become an account takeover.
- Arne Swinnen deliberately chains lower-impact findings into higher-impact PoCs.
- Orange Tsai's entire research philosophy is built on combining 3–4 individually modest issues into pre-auth RCE.
- filedescriptor chained out-of-scope XSS to session fixation.
- Brett Buerhaus escalated a PhantomJS XSS to SSRF to AWS key disclosure.

**Mental model:** Never dismiss a finding until you understand its maximum reachable impact.

### 3. Understanding Systems Architecturally
Orange Tsai is the clearest example, but the pattern appears everywhere: the best hunters think about how components of a system interact, not just what individual parameters do. Sam Curry found the same SSO failure pattern across 16 car manufacturers because he understood the architectural pattern, not just the surface manifestation.

### 4. Feature-Based vs. Parameter-Based Testing
Top hunters test *features* (what does this feature need to do to work? what could go wrong architecturally?) rather than spraying parameters with payloads. This is explicitly articulated by STÖK, yassineaboukir, filedescriptor, and Sam Curry.

### 5. Developer Mental Model
Frans Rosen's maxim: "If you are a developer, try think of times when you thought 'Oh shit, I did this wrong.'" Patrik Fehrenbach and Brett Buerhaus both emphasize understanding what the developer was trying to build before probing it. This gives hunters an edge over purely adversarial testers.

### 6. Automation Polarity: The Two Schools
There are two successful schools:
- **Manual-first:** Ron Chan (Burp only, no automation), Tommy DeVoss (hunts "old-school"), yassineaboukir.
- **Automation-first:** todayisnew (99% automated), Sergey Toshin/bagipro (scans hundreds of apps), Shubham Shah (custom asset monitoring), XBOW (fully automated).

Notably, the manual-first hunters tend to dominate at **high-complexity vulnerability chains** and **impact escalation**. The automation-first hunters dominate at **volume** and **asset coverage**. Both can be highly profitable.

### 7. Time-to-Bounty as a Selection Signal
Multiple top hunters (Mark Litchfield, Sam Curry, Tommy DeVoss, inhibitor181) rank programs partly by speed of payout. This is rational: a slow program consumes time through follow-up and delays, effectively reducing hourly rate. The best hunters treat their time as an economic asset.

### 8. Community and Writeups as Core Infrastructure
Every hunter interviewed cites disclosed reports on HackerOne Hacktivity, Twitter follows, and peer writeups as primary education. Ron Chan credits a single zseano writeup with transforming his career. nahamsec built his methodology from a mental checklist built by reading others' reports. The community is not competition — it's the curriculum.

### 9. Program Timing
Frans Rosen identified three phases of a program's lifecycle:
- **Launch** (high duplication, low return)
- **Middle** (variable)
- **6–18 months in** (best opportunity — new code deployed, competition drops, teams trust reporters)

### 10. Specialization vs. Generalism
The highest earners tend to have a **primary vulnerability class specialization** while maintaining generalist awareness:
- Santiago Lopez → IDOR
- Tommy DeVoss → SSRF, RCE
- Ron Chan → OAuth/auth chains
- Sergey Toshin → Android mobile
- Frans Rosen → OAuth, postMessage, S3
- Orange Tsai → RCE chains via architectural confusion
- Corben Leo → SSRF

The specialization provides pattern recognition that dramatically accelerates finding. They've seen the same class of bug so many times that variants are immediately recognizable.

---

## Part 5: Direct Quotes Database

**On getting started:**
- nahamsec: "The first bug is always the hardest, but once you find that first one, everything becomes a bit easier."
- nahamsec: "Understand how applications work instead of jumping in and copy/pasting payloads."
- inhibitor181: "Bug bounty is not something you learn in a few months — it has an extremely steep learning curve."
- Patrik Fehrenbach: "Don't hunt just for money, hunt for knowledge, hunt for fun."
- Ron Chan: "Keep reading the write-ups and replicate it in your local environment when you don't understand it."
- Ron Chan: "Bug bounty — No risk and high return, the only investment is your time."

**On methodology:**
- STÖK: "I approach each new target one host at a time. Gracefully, I do my recon, enumerate the hosts, do my content discovery, map out the terrain, study the app, read the docs."
- STÖK: "I don't understand most code, so I have to rely on deep understanding of design flows and figuring out what the developers missed."
- nahamsec: "Something that may be obvious to one person, may not be as obvious to another. So always approach a target without considering other hackers that have already looked at the program."
- Frans Rosen: "If you are a developer, try think of times when you thought 'Oh shit, I did this wrong.'"
- filedescriptor: "You most often just need to change one parameter and it's already a critical bug."
- Shubham Shah: "When you submit bugs, remember that you aren't actually entitled to anything."

**On persistence:**
- Arne Swinnen: "Persist. There's always something that has been overlooked."
- Frans Rosen: "Keep digging. Really. You will have times where you just want to quit."
- Frans Rosen: "I read A LOT. The interesting thing here is that you can never read too much."

**On program/target selection:**
- Mark Litchfield: "How well do they respond, how quick do they fix / pay."
- Sam Curry: "The time it takes for a submission to receive a bounty is as important as the actual bounty amount."
- Santiago Lopez: "I care less about whether they are private or public, and care more about the scope."
- Nathaniel Wakelam: "Bug bounties are a time investment and if you aren't getting a return on that, reassess your strategy."

**On motivation:**
- inhibitor181: "The main motivator for me is the money I earn."
- Tommy DeVoss: "The amount of money that you can make doing this legally far outweighs the money you're gonna make illegally."
- Santiago Lopez: "Not because of the money, but because this achievement represents the information of companies and people being more secure."
- Mark Litchfield: "Hacking can open doors to anyone with a laptop and curiosity about how to break things."

**On Orange Tsai's research philosophy:**
- "Could I use a single HTTP request to access different contexts in Frontend and Backend to cause confusion?"
- ProxyLogon: "If the entrance of Exchange is 0, and 100 is the core business logic, ProxyLogon is somewhere around 10."
- Apache: "The modules do not fully understand each other, yet they are required to cooperate."

---

## Part 6: Key Resources

- **HackerOne Hacktivity** — disclosed reports; the community's primary curriculum
- **Bugcrowd Levelup** — conference talks and methodology presentations
- **nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters** — GitHub
- **jhaddix/tbhm** — The Bug Hunters Methodology (GitHub)
- **zseano's Methodology** — available at bugbountyhunter.com
- **blog.orange.tw** — Orange Tsai's research blog
- **samcurry.net** — Sam Curry's writeups
- **labs.detectify.com** — Frans Rosen, Mathias Karlsson, Tom Hudson research
- **rhynorater.github.io** — Justin Gardner's blog
- **Critical Thinking Bug Bounty Podcast** — criticalthinkingpodcast.io (hosted by Rhynorater, Rez0, gr3pme)
- **shubs.io** — Shubham Shah's blog
- **ngailong.wordpress.com** — Ron Chan's writeups
- **blog.oversecured.com** — Sergey Toshin's Android research
- **arneswinnen.net** — Arne Swinnen's writeups
- **corben.io** — Corben Leo's blog
- **portswigger.net/research** — James Kettle's research
- **jameskettle.com** — James Kettle's portfolio
- **BugBountyForum AMAs** — bugbountyforum.com/blog/ama/ (direct interviews with many hunters)
