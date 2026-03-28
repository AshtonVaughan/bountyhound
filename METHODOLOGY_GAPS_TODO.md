# BountyHound Methodology Gaps - Action List
Compiled March 2026 from top 20 bug bounty hunter analysis

=== THIS WEEK (Zero/Low Effort, High Impact) ===

[ ] gf named pattern pipeline (tomnomnom)
    waybackurls target.com | gf aws-keys
    waybackurls target.com | gf takeovers
    waybackurls target.com | gf php-sinks
    waybackurls target.com | gf cors
    Install: go install github.com/tomnomnom/gf@latest
    Patterns: github.com/tomnomnom/gf/tree/master/examples

[ ] cent + Nuclei community templates
    cent init && cent update
    nuclei -l live.txt -t ./cent-nuclei-templates -tags cve,misconfig,exposure
    Install: go install github.com/xm1k3/cent@latest

[ ] haklistgen - target-specific wordlists
    cat live.txt | while read url; do curl $url -sk | haklistgen | anew wordlist.txt; done
    10x hit rate vs generic wordlists
    Install: go install github.com/hakluke/haklistgen@latest

[ ] hakcsp - CSP header domain mining
    cat live.txt | hakcsp -t 8
    CSP headers expose org-controlled domains = free scope expansion
    Install: go install github.com/hakluke/hakcsp@latest

[ ] 401 to bruteforce-under-it (jhaddix)
    When dir discovery hits 401: re-run wordlist targeting paths UNDER that dir
    /admin/ -> 401 -> run wordlist against /admin/[word]

[ ] NXDOMAIN preservation
    Stop filtering NXDOMAIN from subdomain enum
    Feed NXDOMAIN results into NS/MX takeover checker separately
    0xpatrik found 12,888 vulnerable domains this way

[ ] unfurl --unique keys param wordlist
    waybackurls target.com | unfurl --unique keys > custom_params.txt
    Use as Burp Intruder param list instead of generic wordlist
    Install: go install github.com/tomnomnom/unfurl@latest

=== THIS MONTH (Medium Effort, High Impact) ===

[ ] CI/CD log scraping pipeline
    secretz <org> - Travis CI full org build logs + ripgrep for secrets
    Patterns: export, token=, key=, password=, BEGIN RSA PRIVATE KEY, [secure]
    Install: go install github.com/lc/secretz@latest

[ ] JS endpoint mining
    cat live.txt | subjs > js_files.txt
    Run relative-url-extractor on each JS file -> hidden API routes
    Install subjs: go install github.com/lc/subjs@latest
    gem install relative-url-extractor

[ ] hakoriginfinder - WAF/CDN origin discovery
    prips 93.184.216.0/24 | hakoriginfinder -h https://target.com -p 80,443,8080,8443 -l 5
    Finds real origin IP behind Cloudflare/Akamai - bypass WAF entirely
    Install: go install github.com/hakluke/hakoriginfinder@latest

[ ] SSRF canary chain strategy (shubs)
    SSRF found -> chain to internal service that makes outbound requests
    Internal service -> canary hit = confirmed access + service fingerprint
    Use interactsh-client for callbacks

[ ] Gopherus - SSRF to RCE via Gopher protocol
    Redis cron RCE, FastCGI PHP injection, Memcache object injection
    git clone https://github.com/tarunkant/Gopherus

[ ] DNS ELB to internal service inference
    *.elb.amazonaws.com resolving to 10.x = internal service
    Infer service from ELB name -> target via SSRF on relevant port
    9200=Elasticsearch, 6379=Redis, 11211=Memcache, 8983=Solr

[ ] Real-time CT log monitoring (hakcertstream)
    hakcertstream - watches for new certs issued in real-time
    New cert = new subdomain = unreviewed code = first mover wins
    Install: go install github.com/hakluke/hakcertstream@latest

[ ] RFC 3986 mass 401/403 bypass (massbypass)
    Run against every access-denied endpoint before manual work
    100+ path manipulation patterns: double encode, Unicode normalize, dot segments
    Repo: github.com/nullenc0de/massbypass

[ ] GitHub dork automation
    python gh-dork.py -d dorks.txt -org targetcorp -o results/
    Dorks: org_name password, filename:travis.yml, extension:pem private
    Repo: github.com/hakluke/gh-dork

[ ] hakip2host - IP range to hostname (PTR + SSL SANs + SSL CNs)
    echo target.com | haktrails associatedips | prips | hakip2host | anew subs.txt
    Install: go install github.com/hakluke/hakip2host@latest

[ ] ActiveScanPlusPlus Burp extension (shubs)
    Host header attacks, SSTI detection (7*7=49), blind injection, Shellshock, Struts/Rails CVEs
    Repo: github.com/albinowax/ActiveScanPlusPlus

[ ] enumXFF - 403 bypass via X-Forwarded-For IP brute
    python enumXFF.py -t http://target.com/admin -r 192.168.0.0-192.168.255.255
    Repo: github.com/infosec-au/enumXFF

=== STRATEGIC (Long-term Competitive Edge) ===

[ ] Trust graph analysis before hunting (Sam Curry approach)
    Map SSO relationships across portals before testing
    Find acquisition bridges (partner portal -> employee LDAP)
    Identify /bff/proxy/ and reverse proxy hints in responses
    Look for UUID/ID params crossing resource boundaries without ownership check

[ ] Acquisition hunting
    Wikipedia List of mergers and acquisitions for target company
    Trademark search -> domains not listed in program scope
    Privacy policy text search -> shared infrastructure across brands

[ ] IIS Shortname + BigQuery (shubs novel technique)
    IIS Shortname Scanner -> e.g. SITEBA~1.ZIP
    Query GitHub BigQuery public dataset to recover full filename
    First free TB of BigQuery monthly = free technique

[ ] Heap dump forensics (samwcyo)
    /actuator/heapdump accessible -> Eclipse Memory Analyzer
    Search session cookie variable names -> extract live authenticated sessions

[ ] Self-hosted OOB callback server
    Port 8443 with self-signed cert (tests SSL validation before redirect = SSRF extension)
    Options: jobertabma/ground-control or honoki/wilson-cloud-respwnder

[ ] Continuous recon diff model (jobertabma)
    Git-track all recon output - same command weekly -> git diff shows what changed
    New ports, new subdomains, new JS endpoints = alert

[ ] RFC-based methodology (EdOverflow)
    Before testing any protocol: read RFC Security Considerations section
    IETF Rfcdiff to compare old vs current RFC versions
    Implementation deviations from spec = vulnerabilities

===  TOP-50 GAPS (added March 2026 from hunters 1–50 analysis) ===

[x] HTTP request smuggling probe — smuggler.py installed to C:/Users/vaugh/Desktop/Tools/smuggler
    Detection: CL.TE/TE.CL, header obfuscation variants (xchunked, space-before-colon, tab)
    Escalation: cache poisoning, response queue poisoning, credential theft
    Source: albinowax

[x] Reverse proxy auth bypass pattern — added to phased-hunter trigger map
    Look for _api/<service>/, /bff/proxy/, /_api/ — call without auth, check if 3rd party data returns
    Source: securinti (KuCoin $1M chain)

[x] WHATWG vs RFC3986 URL parser split probe — added to phased-hunter Step 1
    Probe: https://attacker.com\@target.com on all URL-accepting params
    Source: xdavidhu ($5k+ Google Cloud SSRF chain)

[x] Content-type switching for hidden parsers — added to phased-hunter Step 1 + XXE trigger
    JSON POST → Content-Type: text/xml + XXE payload → silent dual-parser backends
    Source: harshbothra- (SecurityExplained S-14)

[x] AI/LLM attack surface — added to trigger map + playbook priority #6
    Prompt injection, markdown image exfiltration, invisible Unicode, system prompt extraction
    Source: rez0 (jthack)

[x] Helpdesk email trust chain — added to trigger map + hunt.md step 20
    Zendesk email verification + target SSO trust = SSO bypass without password
    Source: regala_

[x] Second-order injection probe — added to phased-hunter Step 1
    Stored data revisited in all rendering contexts (PDF, email, admin log)
    Source: mhmdiaa (second-order tool)

[x] GraphQL path enumeration — added to playbook testing approach
    Test auth on each path to sensitive types independently, not just primary path
    Source: dee-see (graphql-path-enum)

[x] Nameserver pivot — added to hunt.md step 17
    dig NS target.com → SecurityTrails pivot → find undisclosed subsidiaries
    Source: streaak

[x] Historical JS endpoint extraction — added to hunt.md step 18
    gau --providers wayback + Wayback fetch → extract deleted API routes
    Source: mhmdiaa (chronos/jsluice)

[x] Local DTD gadgets for blind XXE — added to XXE trigger map row
    /etc/xml/catalog, xml-commons-resolver*.jar for error-based exfil without outbound
    Source: dee-see (dtd-finder)

[x] PDF renderer SSRF via XSS — added to XXE trigger map row
    XSS → iframe src=attacker → Prince/wkhtmltopdf fetches URL server-side
    Source: securinti (CVE-2018-19858)

[x] CORS+XSS chain — added to CORS trigger map row
    Permissive CORS + stored XSS = full cross-origin data exfiltration
    Source: securinti (Yahoo contacts)

[x] Safari backtick CORS bypass — added to CORS trigger map row
    origin https://attacker.com`victim.com — some validators fail on backtick
    Source: multiple hunters

[x] SubOver scanner — go install running (Ice3man543/SubOver)
    51+ vulnerable service fingerprints, faster than alternatives
    Source: streaak

[x] chronos Wayback OSINT tool — building from git clone
    Modular historical data extraction: jsluice, favicon hash, regex, XPath
    Source: mhmdiaa

[x] second-order scanner — go install running (mhmdiaa/second-order)
    Detects stored data reflected in different context than where entered
    Source: mhmdiaa

[x] cewlai — AI domain generation — cloned to C:/Users/vaugh/Desktop/Tools/cewlai
    Source: rez0

[x] RPO (Relative Path Overwrite) — added to phased-hunter trigger map after Path traversal row
    /path/page → navigate to /path/page/injected → browser resolves relative CSS/JS to wrong path
    Source: filedescriptor

[x] N×N role-permission matrix — added to hunting-playbook.md IDOR section
    Source: harshbothra-

[x] Unicode overflow WAF bypass — added to waf-bypass/references/techniques.md
    Codepoints >255 truncate mod 256: 0x4e41 % 256 = 'A' — bypasses character blocklists
    Python generator included, Hackvertor reference included
    Source: albinowax

[x] crt.sh PostgreSQL direct query — added to hunt.md step 23
    psql -h crt.sh -U guest -d certwatch with API fallback
    Source: multiple hunters (batch 41-50)

[x] alterx for permutation generation — installed (alterx.exe in go/bin), added to hunt.md step 21
    Source: ProjectDiscovery ecosystem (batch 31-40)

[x] chaos-client for pre-built subdomain data — installed (chaos.exe in go/bin), added to hunt.md step 22
    Source: multiple hunters (batch 41-50)

=== KEY REFERENCES ===

tomnomnom    Pipeline tools + gf       github.com/tomnomnom
nahamsec     Lazyrecon                 github.com/nahamsec/lazyrecon
jasonhaddix  TBHM methodology          github.com/jhaddix/tbhm
zseano       Input surface mapping     github.com/zseano/InputScanner
nullenc0de   Cloud + 403 bypass        github.com/nullenc0de
samwcyo      Logic chain attacks       samcurry.net/blog
jobertabma   OOB + virtual hosts       github.com/jobertabma
yassine      SSRF + CT monitoring      github.com/yassineaboukir/sublert
EdOverflow   CI/CD + RFC method        github.com/EdOverflow/bugbounty-cheatsheet
0xpatrik     Subdomain takeover        0xpatrik.com
lc           gau + secretz             github.com/lc
hakluke      Pipeline ecosystem        github.com/hakluke
shubs        SSRF chains               blog.assetnote.io
KathanP19    HowToHunt community       github.com/KathanP19/HowToHunt
honoki       BBRF + DNS rebind         github.com/honoki
