# SKILL: OSINT Tools

## Metadata
- **Skill Name**: osint-checklist
- **Folder**: offensive-osint
- **Source**: https://github.com/SnailSploit/offensive-checklist/blob/main/osint.md

## Description
Practical OSINT checklist: domain recon, email harvesting, social media profiling, GitHub/code leaks, Shodan/Censys enumeration, breach data lookup, employee profiling, and infrastructure mapping. Use for bug bounty recon, red team intelligence gathering, or corporate OSINT.

## Trigger Phrases
Use this skill when the conversation involves any of:
`OSINT, reconnaissance, domain recon, email harvesting, Shodan, Censys, GitHub recon, breach data, employee profiling, infrastructure mapping, corporate OSINT`

## Instructions for Claude

When this skill is active:
1. Load and apply the full methodology below as your operational checklist
2. Follow steps in order unless the user specifies otherwise
3. For each technique, consider applicability to the current target/context
4. Track which checklist items have been completed
5. Suggest next steps based on findings

---

## Full Methodology

# OSINT Tools

- [Bookmarks](https://tools.myosint.training/): Comprehensive list of various OSINT bookmarks.
- [OSINT Framework](https://osintframework.com/): A comprehensive collection of OSINT tools and resources.

## General OSINT

- [IntelTechniques Tools](https://inteltechniques.com/tools/): A suite of OSINT tools for various investigative needs.
- [Online Investigation Toolkit](https://www.bellingcat.com/resources/2024/09/24/bellingcat-online-investigations-toolkit/): A curated list of tools used by investigative journalists
- [CyberSudo OSINT Toolkit](https://docs.google.com/spreadsheets/d/1EC0sKA_W9znzsxUt0wye9UYtyATXw5m8): List of OSINT Websites
- [GeoGuesser Top Tips](https://somerandomstuff1.wordpress.com/2019/02/08/geoguessr-the-top-tips-tricks-and-techniques/): Top Tips and Tricks for Geolocation
- [Google Dorks](https://dorksearch.com/): Helps you search google more efficiently
- [Country Specific Resources](https://digitaldigging.org/osint/): To help you specifically look for things a certain country
- [Distributed Denial of Secrets](https://ddosecrets.com/): Leaked Data

### Search Engines

- [Carrot2](https://search.carrot2.org/#/search/web): organizes your search results into topics
- [etools](https://www.etools.ch/): metasearch engine
- [PDF Search](https://www.pdfsearch.io/): searching for PDF files and viewing their table of content
- [Kagi Search](https://kagi.com/): privacy-first search with Lenses and non-personalized results
- [Brave Search](https://search.brave.com/): independent index; Goggles for custom ranking
- [Google Fact Check Explorer](https://toolbox.google.com/factcheck/explorer): cross-site fact-check search

### Username and Email Investigation

- [What's My Name](https://whatsmyname.app/): Search for usernames across multiple platforms.
- [Maigret](https://github.com/soxoj/maigret): Collect profiles from various sites by username.
- [NameCheckup](https://namecheckup.com/): Find Available Username
- [Holehe](https://github.com/megadose/holehe): Check if an email is registered on online platforms.
- [EmailRep](https://emailrep.io/): Check email reputation and associated data.
- [Namechk](https://namechk.com/): Check username availability across multiple platforms.
- [Hunter.io](https://hunter.io/): Find email addresses associated with a domain.
- [Sherlock](https://github.com/sherlock-project/sherlock): Find usernames across social networks.
- [PhoneInfoga](https://github.com/sundowndev/phoneinfoga): Information gathering framework for phone numbers
- [ContactOut](https://contactout.com/): Discover Email Addresses
- [Emailable](https://emailable.com/): Verify if Email exists
- [GetProspect Extension](https://chromewebstore.google.com/detail/email-finder-getprospect/bhbcbkonalnjkflmdkdodieehnmmeknp?hl=en)
- [SignalHire Extension](https://chrome.google.com/webstore/detail/signalhire-find-email-or/aeidadjdhppdffggfgjpanbafaedankd)
- [OSINT Industries](https://osint.industries/): Email/username/phone lookups
- [Mugetsu](https://mugetsu.io/): X/Twitter username history & meme coin lookups
- [Epieos](https://epieos.com/): Email address pivots and metadata (when available)
- [RocketReach](https://rocketreach.co/) / [Apollo](https://www.apollo.io/) / [Dropcontact](https://www.dropcontact.com/) : Enrichment and email pattern guessing

### People Search

- [WhitePages](https://www.whitepages.com/): Find people and contact information
- [TruePeopleSearch](https://www.truepeoplesearch.com/): Free people search in the U.S.
- [Pipl](https://pipl.com/): Deep web people search (Note: primarily a paid service).
- [Spokeo](https://www.spokeo.com/): People search engine.
- [Webmii](https://webmii.com/): People search engine
- [Clearbit](https://clearbit.com/): Data enrichment for companies and individuals.
- [FaceCheck](https://facecheck.id/): Find people by their picture
- [FaceSeek](https://faceseek.online/): another reverse search for faces

### Social Media

- [Search4Faces](https://search4faces.com/): search for a face in social media.
- [Picuki](https://www.picuki.com/): View Instagram profiles and posts without an account.
- [snscrape](https://github.com/snscrape/snscrape): Actively‑maintained CLI scraper for X/Twitter, Reddit, Telegram, and more. Prefer this over Twint.
- Twint (unstable; breaks when APIs change) — use only if `snscrape` cannot cover a need.
- [Social Blade](https://socialblade.com/): Analytics for YouTube, Twitch, Instagram, and more.
- [Facebook Graph Search](https://inteltechniques.com/tools/Facebook.html): Advanced Facebook search techniques.
- [Facebook Friends](https://sowsearch.info/): graph search alternative
- [Facebook ID Lookup](https://lookup-id.com/): to find ID of a user on Facebook
- [Facebook Search](https://whopostedwhat.com/): searching for posts
- [Meta Content Library](https://transparency.meta.com/researcher): Researcher‑gated content search (CrowdTangle successor)
- [Tokboard](https://tokboard.com/): TikTok trend and profile analytics (APIs change frequently)
- [Reveddit](https://www.reveddit.com/): View removed Reddit content for context
- [RedTrack.social](https://redtrack.social/): Reddit user analysis and post history tracking
- **Threads by Instagram**: Use Instagram OSINT tools; Threads shares Instagram account infrastructure
- **Bluesky/AT Protocol**:
  - [Firesky](https://firesky.tv/): Real-time firehose monitoring for keywords/hashtags
  - [SkyView](https://bsky.jazco.dev/): Follower graphs and network analysis
  - [Bluesky Directory](https://blueskydirectory.com/): User directory and starter pack discovery
- **Mastodon/Fediverse**:
  - [FediSearch](https://fedisearch.skorpil.cz/): Cross-instance post search
  - [Fediverse Observer](https://fediverse.observer/): Instance enumeration and stats
  - [Fediverse.party](https://fediverse.party/): Platform directory and network map
  - [Fedifinder](https://fedifinder.glitch.me/): Find Twitter/X users on Mastodon

### Phone Number

- [TrueCaller](https://www.truecaller.com/): Caller ID and Spam Blocking App
- [CallerIDTest](https://calleridtest.com/): Phone Search
- [Infobel](https://infobel.com/): Phone search outside of USA
- [ThatsThem](https://thatsthem.com/): Reverse phone search
- [Advanced Background Checks](https://www.advancedbackgroundchecks.com/): shows all people that used the phone number
- [FreeCarrierLookup](https://freecarrierlookup.com/): Carrier/type lookup for US numbers
- [NumlookupAPI](https://numlookupapi.com/) [Freemium]: Programmatic carrier/line-type checks

### Public Records and Company Information

- [OpenCorporates](https://opencorporates.com/) : World's largest open database of companies.
- [SEC EDGAR](https://www.sec.gov/edgar.shtml): U.S. Securities and Exchange Commission's database for company filings.
- [OpenOwnership Register](https://register.openownership.org/): Beneficial ownership datasets
- [EU Tenders (TED)](https://ted.europa.eu/): EU public procurement notices
- [World Bank Projects & Operations](https://projects.worldbank.org/): Project and procurement records
- [IFC Disclosure](https://disclosures.ifc.org/): Project disclosures and documents
- [MuckRock](https://www.muckrock.com/): FOIA repository and request tracking

### Leaks

- [Have i been pwned](https://haveibeenpwned.com/)
- [PwdQuery](https://pwdquery.xyz/)
- [LeakCheck](https://leakcheck.io/)
- [Scattered Secrets](https://scatteredsecrets.com/)
- [Dehashed](https://dehashed.com/)
- [IntelX](https://intelx.io/)
- [Phonebook](https://phonebook.cz/)
- [LeakPeek](https://leakpeek.com/): Database breach lookups
- [Snusbase](https://snusbase.com/): Database breach lookups
- [BreachDirectory](https://breachdirectory.org/): Search credentials exposed in recent breaches
- [Snusmap](https://snusmap.com/): Visual browser for leaked‑data collections
- [Cavalier (Hudson Rock)](https://cavalier.hudsonrock.com/): Infostealer lookups
- [Pwned Passwords API](https://haveibeenpwned.com/): K‑anonymity password checks without revealing the full hash

## Cryptocurrency OSINT

### Blockchain Analysis

- [Blockchain.com Explorer](https://www.blockchain.com/explorer): Bitcoin and crypto search engine
- [Etherscan](https://etherscan.io/): Ethereum blockchain explorer
- [BSCScan](https://bscscan.com/): BNB Smart Chain explorer
- [PolygonScan](https://polygonscan.com/): Polygon PoS blockchain explorer
- [OKLink](https://www.oklink.com/) [Freemium]: Multichain explorer and analytics
- [Cielo](https://cielo.io/): Multi-chain wallet tracking (EVM, Bitcoin, Solana, Tron, etc)
- [Blockchair](https://blockchair.com/): Bitcoin block explorer
- [Solscan](https://solscan.io/): Solana blockchain explorer
- [Dune](https://dune.com/): Analytics platform to query blockchain data
- [MetaSuites](https://metasuites.io/): Chrome extension for additional data on block explorers
- [Impersonator](https://impersonator.xyz/): Chrome extension to spoof login to dApps

#### Layer 2 / Rollup Explorers

- [zkSync Era Explorer](https://explorer.zksync.io/): zkSync Era (zkEVM) block explorer
- [Polygon zkEVM Explorer](https://zkevm.polygonscan.com/): Polygon zkEVM rollup
- [Arbiscan](https://arbiscan.io/): Arbitrum One and Nova explorers
- [Optimistic Etherscan](https://optimistic.etherscan.io/): Optimism mainnet explorer
- [BaseScan](https://basescan.org/): Base (Coinbase L2) explorer
- [Voyager](https://voyager.online/) / [StarkScan](https://starkscan.co/): StarkNet block explorers
- [Scroll Explorer](https://scrollscan.com/): Scroll zkEVM explorer
- [Blast Explorer](https://blastscan.io/): Blast L2 explorer
- [L2Beat](https://l2beat.com/): Risk analysis, TVL, and technology comparison for all L2s
- [Growthepie](https://www.growthepie.xyz/): L2 metrics and analytics aggregator

### Wallet Investigation

- [BitcoinAbuse](https://www.bitcoinabuse.com/): Track bitcoin addresses used for scams
- [Wallet Explorer](https://www.walletexplorer.com/): Bitcoin wallet transaction clustering
- [Chainalysis](https://www.chainalysis.com/): Professional blockchain analysis platform
- [Crystal Blockchain](https://crystalblockchain.com/): Blockchain analytics and monitoring

### Transaction Tracking

- [Whale Alert](https://whale-alert.io/): Track large crypto transactions
- [BitQuery](https://bitquery.io/): Blockchain data analysis and APIs
- [GraphSense](https://graphsense.info/): Cryptocurrency analytics platform
- [CipherTrace](https://ciphertrace.com/): Cryptocurrency intelligence
- [TRM](https://www.trmlabs.com/): Create graphs for addresses/transactions
- [Arkham](https://www.arkhamintelligence.com/): Multichain block explorer, entity labels, graphs, alerts
- [MetaSleuth](https://metasleuth.io/): Similar to TRM but intended for retail users
- [CryptoTaxCalculator](https://cryptotaxcalculator.io/): Track PNL for an address
- [Breadcrumbs](https://www.breadcrumbs.app/) [Freemium]: Visual graphing and labeling for crypto flows
- [Bubblemaps](https://bubblemaps.io/): Holder concentration visualization; identify whale clusters
- [Token Sniffer](https://tokensniffer.com/): Honeypot and scam token detection
- [Dextools](https://www.dextools.io/): DEX trading analysis and charts
- [Nansen](https://www.nansen.ai/): On-chain analytics with Smart Money labels (paid; expensive)

### Bridge Monitoring

- [Range](https://range.org/): CCTP bridge explorer
- [Pulsy](https://pulsy.io/): Bridge explorer aggregator
- [Socketscan](https://socketscan.io/): EVM bridge explorer
- [L2Beat Bridges](https://l2beat.com/bridges) [Free]: Risk analysis for bridges and tokens

### NFT Analysis

- [OpenSea](https://opensea.io/): NFT marketplace explorer
- [NFTScan](https://www.nftscan.com/): Multi-chain NFT explorer
- [Nansen](https://www.nansen.ai/): NFT analytics platform
- [DappRadar](https://dappradar.com/): Track NFT sales and marketplace activity
- [Reservoir](https://reservoir.tools/) [Freemium]: Unified NFT metadata and market data API
- [Alchemy NFT API](https://www.alchemy.com/nft-api) [Freemium]: NFT metadata and ownership APIs

### Exchange Intelligence

- [CoinGecko](https://www.coingecko.com/): Cryptocurrency market data
- [CoinMarketCap](https://coinmarketcap.com/): Price tracking and market analysis
- [Binance Intelligence](https://www.binance.com/en/feed): Exchange activity monitoring
- [Glassnode](https://glassnode.com/): On-chain market intelligence

## Media Intelligence

### Image Analysis

- [Google reverse image search](https://images.google.com/): reverse image search engine.
- [TinEye](https://tineye.com/): reverse image search.
- [Yandex images](https://yandex.com/images/): effective for Russian and eastern European content.
- [PimEyes](https://pimeyes.com/en): change a picture and then search
- [Forensically](https://29a.ch/photo-forensics/): ToolSet for digital image forensics.
- [Getty](https://www.gettyimages.com/)
- [Shutterstock](https://www.shutterstock.com/)
- [Alamy](https://www.alamy.com/)

### Browser Extensions

- [Fake News Debunker by InVID & WeVerify](https://chrome.google.com/webstore/detail/fake-news-debunker-by-inv/mhccpoafgdgbhnjfhkcmgknndkeenfhe): Verifies images and videos.
- [RevEye Reverse Image Search](https://chrome.google.com/webstore/detail/reveye-reverse-image-sear/kejaocbebojdmebagkjghljkeefgimdj): Reverse image search extension.
- [EXIF Viewer Pro](https://chrome.google.com/webstore/detail/exif-viewer-pro/mmbhfeiddhndihdjeganjggkmjapkffm): View EXIF data in-browser.
- [Wayback Machine Extension](https://chrome.google.com/webstore/detail/wayback-machine/fpnmgdkabkmnadcjpehmlllkndpkmiak): Quick access to archived web pages.
- [Search by Image](https://chromewebstore.google.com/detail/search-by-image/cnojnbdhbhnkbcieeekonklommdnndci?hl=en): reverse image search tool, with support for various search engines

### Video Analysis

- [YouTube Data Viewer](https://citizenevidence.amnestyusa.org/): Extract metadata from YouTube videos.
- [InVID & WeVerify Video Verification Tool](https://www.invid-project.eu/tools-and-services/invid-verification-plugin/): Browser extension for video verification.
- [Frame-by-Frame Video Player](https://sourceforge.net/projects/framebyframevideo/): Analyze videos frame by frame.
- [YouTube Geo Tag](https://mattw.io/youtube-geofind/location): Find location of a video via geo tags
- Snap Map (public stories) for area/event context

### Metadata Extraction

- [Jimpl](https://jimpl.com/)
- [ExifTool](https://exiftool.org/): Read, write, and edit metadata.
- [Jeffrey's image metadata viewer](http://exif.regex.info/exif.cgi): online image metadata viewer.
- [MediaInfo](https://mediaarea.net/en/MediaInfo): Technical and tag information about video or audio files.
- [FOCA](https://www.elevenpaths.com/labstools/foca): Analyze metadata and hidden information in documents.
- [Metagoofil](https://www.edge-security.com/metagoofil.php): Extract metadata from public documents.

## GeoSpatial Intelligence

### Satellite Imagery and Mapping

- [Google Maps](https://www.google.com/maps): Mapping and satellite imagery.
- [Bing Maps](https://www.bing.com/maps/): Alternative mapping service.
- [NOAA Maps](https://coast.noaa.gov/dataviewer/#/imagery/search/): Coastal imagery.
- [NASA FIRMS](https://firms.modaps.eosdis.nasa.gov/map/): Fire data and HotSpots.
- [OpenStreetMap](https://www.openstreetmap.org/): Open-source map of the world.
- [Sentinel Hub EO Browser](https://apps.sentinel-hub.com/eo-browser/): Access to satellite imagery from Sentinel and Landsat.
- [NASA Worldview](https://worldview.earthdata.nasa.gov/): Satellite imagery from NASA.
- [Zoom Earth](https://zoom.earth/) : Live satellite images and weather data.
- [Wayback Imagery](https://livingatlas.arcgis.com/wayback/) : Historical satellite images.
- [Windy](https://www.windy.com/): Live weather map.
- [Open Infrastructure Map](https://openinframap.org/): Visualize global infrastructure(Water, Power, Gas, etc) networks
- [Memento Timemap](https://timetravel.mementoweb.org/): Aggregate archive index for any URL (for map UIs and tiles)

### Tools and Applications

- [Mapillary](https://www.mapillary.com/app): CrowdSourced street-level imagery.
- [KartaView](https://kartaview.org/): Open-source street-level imagery.
- [Overpass Turbo](https://overpass-turbo.eu/): Advanced querying of OpenStreetMap data.
- [SunCalc](https://www.suncalc.org/): Sun position calculator for Chronolocation.
- [PeakVisor](https://peakvisor.com/): Identify mountain peaks.
- [GeoNames](https://www.geonames.org/): Geographical database.
- [SAS Planet](https://www.sasgis.org/sasplaneta/): Satellite imagery viewing application.
- [Marble](https://marble.kde.org/): Virtual globe and world atlas.
- [C2PA Verify](https://verify.contentauthenticity.org/): Verify embedded content credentials

### Street View

- [Google Street View](https://www.google.com/maps): Street-level imagery.
- [Apple Maps](https://maps.apple.com/): Alternative mapping service.
- [Yandex Maps](https://yandex.com/maps/): Russian mapping service with street view.
- [Baidu Maps](https://map.baidu.com/): Chinese mapping service.

### Flight OSINT

- [FlightRadar](https://www.flightradar24.com/)
- [FlightAware](https://www.flightaware.com/)
- [RadarBox](https://www.radarbox.com/)
- [ADSBExchange](https://www.adsbexchange.com/): Unfiltered community ADS‑B flight tracking feed
- [AirFrames](https://www.airframes.org/)
- [Planespotters](https://www.planespotters.net/): Fleet/airframe history and photos by tail number
- [JetPhotos](https://www.jetphotos.com/): Spotter photos for visual confirmation

## Maritime OSINT

- [MarineTraffic](https://www.marinetraffic.com/): Live AIS vessel tracking
- [VesselFinder](https://www.vesselfinder.com/): Global ship movements and port calls
- [FleetMon](https://www.fleetmon.com/): Historical AIS data and analytics
- [Global Fishing Watch](https://globalfishingwatch.org/map/): Fishing vessel behavior and AIS gap analysis

## AI‑Assisted OSINT Platforms

### Commercial/Enterprise AI Tools

- [Cylect](https://www.cylect.io/): AI‑powered entity extraction and link‑analysis workspace
- [Fivecast Matrix](https://www.fivecast.com/products/matrix/): Generative‑AI triage and risk scoring for large social‑media datasets
- [Recorded Future](https://www.recordedfuture.com/): AI-driven threat intelligence and entity tracking
- [DarkOwl Vision](https://www.darkowl.com/): AI-powered darknet data collection and analysis

### AI-Powered Analysis

> [!WARNING]
> Never paste PII, sensitive IOCs, or unique pivots into cloud LLMs; they log inputs and may use for training. Prefer local models (Ollama, LM Studio) for sensitive analysis.

- [OpenAI ChatGPT](https://chat.openai.com/) [Paid for Advanced Data Analysis]: Parse logs, analyze datasets, geo-inference, timeline reconstruction
  - Code Interpreter: Upload CSVs, logs, JSON for automated analysis
  - GPT-4 Vision: Image analysis, OCR, visual geolocation hints
  - **Warning**: OpenAI logs all inputs; do not use for sensitive cases
- [Anthropic Claude](https://claude.ai/) [Paid for Claude 3.5 Sonnet]: Long context (200K tokens) for processing large document dumps, report synthesis
  - Claude Artifacts: Generate interactive visualizations and tools
  - **Warning**: Anthropic logs prompts; sanitize before use
- [Google Gemini](https://gemini.google.com/):
  - Gemini 1.5 Pro: 2M token context (largest available); good for massive log analysis
  - Deep Research mode: Multi-step research automation with citations
  - **Warning**: Google integration risk; assume correlation with search/Gmail data
- [Perplexity Pro](https://www.perplexity.ai/) [Paid]: Real-time web search + reasoning; excellent for context pivots and background research
  - Focus mode: Academic, Reddit, YouTube, or general web
  - Pro search: Deep research with multi-query synthesis
- [Microsoft Copilot](https://copilot.microsoft.com/): Bing-integrated search; good for generic queries
- **Local LLM alternatives** (privacy-preserving):
  - [Ollama](https://ollama.com/): Run Llama 3, Mistral, Qwen locally
  - [LM Studio](https://lmstudio.ai/): GUI for local model inference
  - [GPT4All](https://gpt4all.io/): Privacy-focused local LLM runner

### Specialized AI OSINT Tools

- [C2PA Verify](https://verify.contentauthenticity.org/): Verify Content Credentials and AI provenance metadata
- [Adobe Content Credentials Verify](https://contentcredentials.org/verify): Alternative C2PA verifier
- [Hive Moderation](https://hivemoderation.com/): AI content moderation and CSAM detection
- [CarNet](https://carnet.ai/): Identify car models via AI (useful for geolocation)
- [FingerprintJS](https://fingerprintjs.com/): Browser fingerprinting and bot detection
- [Sensity AI](https://sensity.ai/): Deepfake detection and synthetic media analysis
- [Reality Defender](https://realitydefender.com/): Deepfake and AI-generated content detection

## Archiving & Snapshots

- [archive.today](https://archive.today/): One‑page content archiver with screenshot capability
- [Memento Timemap](https://timetravel.mementoweb.org/): Aggregate index of web archives for any URL
- [URLScan.io](https://urlscan.io/): On‑demand webpage scan with full resource map and screenshot
- Wayback SavePageNow API v3: On‑demand archiving with submission status and job IDs
- WACZ packaging (Webrecorder): Portable, verifiable web archives for replay
- [ArchiveBox](https://archivebox.io/): Self-hosted web archiving; captures HTML, PDF, screenshots, media
- [SingleFileZ](https://github.com/gildas-lormeau/SingleFileZ): Browser extension for offline single-file HTML archives
- [Hunchly](https://www.hunch.ly/): Evidence capture tool for investigators (paid)
- [Kasm Workspaces](https://kasmweb.com/): Containerized OSINT workspace images (browser isolation)

## Automation & Workflows

- [n8n](https://n8n.io/): Self-hosted workflow automation for OSINT pipelines (e.g., monitor RSS → scrape → alert)
- [Huginn](https://github.com/huginn/huginn): Agent-based automation for monitoring, scraping, alerting
- [Cronicle](https://github.com/jhuckaby/Cronicle): Distributed task scheduler for recurring OSINT jobs
- [Apache Airflow](https://airflow.apache.org/): Workflow orchestration for complex data pipelines
- [Prefect](https://www.prefect.io/): Modern workflow orchestration; easier than Airflow

## Additional Tools

### IP and Network Analysis

- [Spur](https://spur.us/): IP lookups and tracking
- [Robtex](https://www.robtex.com/): Passive DNS and infrastructure pivots
- [BinaryEdge](https://www.binaryedge.io/), [FOFA](https://fofa.so/), [ZoomEye](https://www.zoomeye.org/): Infra pivots complementing Shodan/Censys

### ASN/BGP & Internet Measurement

- [Hurricane Electric BGP Toolkit](https://bgp.he.net/): ASN, prefix, peers, and IRR data
- [RIPEstat](https://stat.ripe.net/): IP/ASN history, routing, geolocation, abuse contacts
- [BGPView](https://bgpview.io/): ASN and prefix explorer
- [PeeringDB](https://www.peeringdb.com/): Facility and peering info for networks
- [RADb](https://www.radb.net/), [RIPE IRR](https://www.ripe.net/manage-ips-and-asns/db): Routing policy and contacts
- [RPKI Validators](https://rpki.cloudflare.com/): Route origin and ROA status checks
- [bgp.tools](https://bgp.tools/) [Free]: Clean ASN/IX views, routing details

### Certificates & CT Monitoring

- [crt.sh](https://crt.sh/): Search Certificate Transparency logs
- [Censys Certificates](https://search.censys.io/certificates): CT and x509 attribute pivots
- [CertStream](https://certstream.calidog.io/): Real‑time CT feed (via WebSocket)
- [Rapid7 Open Data](https://opendata.rapid7.com/): Sonar datasets (DNS/HTTP/SSL)
- [Favicons/mmh3](https://github.com/devincao/favicons-hash): Hash favicons to cluster infra; pair with Shodan/Censys favicon search
- [Cert Spotter](https://sslmate.com/certspotter) [Freemium]: CT monitoring and alerts
- [Let's Debug](https://letsdebug.net/) [Free]: Diagnose certificate issuance issues

### Social Media Intelligence

- [Discord ID](https://discord.id/): Basic Discord account information
- [TelegramDB Search Bot](https://t.me/TGdb_bot): Basic Telegram OSINT
- [TGStat](https://tgstat.com/): Channel statistics and message search
- Bluesky explorers (e.g., SkyView), Mastodon handle/instance resolvers

### Telegram & Messaging Analytics

- [TGStat](https://tgstat.com/): Channel analytics and search
- [Telemetr](https://telemetr.io/): Channel growth, overlaps, forwards
- [Combot](https://combot.org/): Group analytics (partially paid)
- [t.me/s/<channel>](https://t.me): Public channel feed view (replace with channel name)
- WeChat OA search via [Sogou Weixin](https://weixin.sogou.com/): Search WeChat Official Accounts content

### Infrastructure & Attack‑Surface OSINT

- [Shodan](https://www.shodan.io/): Search engine for internet‑connected devices and services
- [Censys](https://search.censys.io/): Enumerate hosts and digital certificates across the internet
- [GreyNoise](https://viz.greynoise.io/): Distinguish background internet noise from targeted scans
- [SecurityTrails](https://securitytrails.com/): Passive DNS records and asset discovery
- [SpiderFoot](https://www.spiderfoot.net/): Automated OSINT reconnaissance and correlation (self‑host or SaaS)
- [theHarvester](https://github.com/laramies/theHarvester): Subdomain, email, and metadata harvesting
- [Recon‑ng](https://github.com/lanmaster53/recon-ng): Web‑based recon framework
- [BuiltWith](https://builtwith.com/): Tech stack enumeration; useful for pivoting to third‑party assets
- [Netlas](https://netlas.io/): Large‑scale HTTP/DNS/certificates pivots
- [Amass](https://github.com/owasp-amass/amass) / [Subfinder](https://github.com/projectdiscovery/subfinder) [Free]: Passive subdomain discovery (use responsibly)
- [RiskIQ PassiveTotal](https://community.riskiq.com/): Passive DNS/cert/host pivots

### Threat Intel & IOCs

- Vendor & CERT advisories: CISA/NSA/CSA joint advisories, CERT‑EU, NCSC‑UK, JPCERT/CC, CERT‑UA
- [MISP Project](https://www.misp-project.org/) and public MISP feeds
- [OpenCTI](https://www.opencti.io/): Knowledge graph for CTI (self‑host or SaaS)
- [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/): Malware families, YARA, references
- [abuse.ch ThreatFox](https://threatfox.abuse.ch/), [URLHaus](https://urlhaus.abuse.ch/), [SSLBL](https://sslbl.abuse.ch/)
- [MalwareBazaar](https://bazaar.abuse.ch/): Sample sharing (hash‑based queries)
- [PhishTank](https://www.phishtank.com/), [OpenPhish](https://openphish.com/)

### Malware Analysis & Sandboxes

- Static: [pefile](https://github.com/erocarrera/pefile), [FLOSS](https://github.com/mandiant/flare-floss), [capa](https://github.com/mandiant/capa)
- Similarity: [SSDEEP](https://ssdeep-project.github.io/ssdeep/), [TLSH](https://github.com/trendmicro/tlsh)
- Sandboxes: [ANY.RUN](https://any.run/), [Hybrid Analysis](https://www.hybrid-analysis.com/), [CAPE](https://capesandbox.com/), [Tria.ge](https://tria.ge/)
- Intelligence: [Intezer](https://analyze.intezer.com/) (code reuse), [VirusTotal](https://www.virustotal.com/) (be cautious—uploads become public)
- YARA: [yara](https://virustotal.github.io/yara/), community rules via Malpedia/GitHub repos
- TLS Fingerprints: [JA3](https://github.com/salesforce/ja3), [JA4](https://github.com/FingerprinTLS/ja4)

### RU/CN Corporate & Registries

- Russia: EGRUL/EGRIP (official registries, captcha‑gated), [Rusprofile](https://www.rusprofile.ru/), [Kontur.Focus](https://focus.kontur.ru/) (freemium), [zakupki.gov.ru](https://zakupki.gov.ru/) (procurement)
- Russia media/social: [VK](https://vk.com/), [OK.ru](https://ok.ru/), [Rutube](https://rutube.ru/)
- China: [GSXT](https://www.gsxt.gov.cn/) (National Enterprise Credit Info), [Qichacha](https://www.qcc.com/) / [Tianyancha](https://www.tianyancha.com/) (freemium), [MIIT ICP/Beian](https://beian.miit.gov.cn/) (ICP filings)
- China platforms: [Weibo](https://weibo.com/), [Bilibili](https://www.bilibili.com/), [Zhihu](https://www.zhihu.com/), [Douyin](https://www.douyin.com/)

### Regional Search Engines

- Russia/CIS: [Yandex](https://yandex.com/), [Mail.ru Search](https://go.mail.ru/)
- China: [Baidu](https://www.baidu.com/), [Sogou](https://www.sogou.com/), [360 Search](https://www.so.com/)

### Sanctions & Compliance

- [OFAC SDN List](https://sanctionssearch.ofac.treas.gov/)
- [EU Sanctions Map](https://www.sanctionsmap.eu/)
- [UK Sanctions List (OFSI)](https://www.gov.uk/government/collections/financial-sanctions-regime-specific-consolidated-lists-and-releases)
- [OpenSanctions](https://www.opensanctions.org/): Aggregated persons/entities datasets
- [OCCRP Aleph](https://aleph.occrp.org/): Investigative documents, leaks, company records

## Automation & Headless Browsing

- [Playwright](https://playwright.dev/): Headless browser automation with stealth plugins
- [Browsertrix Crawler](https://github.com/webrecorder/browsertrix-crawler): Archival crawling with WARC export

## Evidence Handling

- Capture URLs, timestamps, and page snapshots (PNG + WARC/SingleFileZ) for every key artifact.
- Hash downloaded files (SHA‑256) and record in your case notes.
- Avoid cross‑contamination: separate work profiles/containers per case; store evidence read‑only.
- Prefer JSONL (NDJSON) logs with a `run_id` and tool versions for reproducibility.

