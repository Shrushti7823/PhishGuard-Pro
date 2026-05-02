
// Multilingual patterns: English + Hindi + Marathi
const patterns = {
    urgency:{
        words:[
            "urgent","immediately","act now","asap","today only","expires soon","limited time",
            "तुरंत","फौरन","तत्काल","अभी तुरंत","अभी कार्यवाही करें","केवल आज","सीमित समय",
            "तत्काळ","लवकरात लवकर","आत्ताच","मर्यादित वेळ","फक्त आज"
        ],
        points:20,icon:"⚡",type:"Urgency Attack"
    },
    fear:{
        words:[
            "suspended","blocked","locked","security alert","account compromised","unauthorized access","virus detected",
            "निलंबित","ब्लॉक","लॉक","सुरक्षा चेतावनी","खाता समझौता","अनधिकृत पहुंच","वायरस पाया गया",
            "निलंबित","ब्लॉक","लॉक","सुरक्षा इशारा","खाते धोक्यात","अनधिकृत प्रवेश","व्हायरस आढळला"
        ],
        points:25,icon:"🚨",type:"Fear Manipulation"
    },
    reward:{
        words:[
            "prize","lottery","winner","gift","reward","congratulations","you won",
            "इनाम","लॉटरी","विजेता","उपहार","पुरस्कार","बधाई","आप जीत गए",
            "इनाम","लाटरी","विजेता","भेट","बक्षीस","अभिनंदन","तुम्ही जिंकलात"
        ],
        points:20,icon:"🎁",type:"Reward Scam"
    },
    finance:{
        words:[
            "bank","paypal","account","payment","verify","credit card","billing","invoice",
            "बैंक","खाता","भुगतान","सत्यापित","क्रेडिट कार्ड","बिल","चालान","राशि",
            "बँक","खाते","पेमेंट","देयक","क्रेडिट कार्ड","बिल","चलन","रक्कम"
        ],
        points:25,icon:"💳",type:"Financial Phishing"
    },
    authority:{
        words:[
            "irs","police","government","amazon support","microsoft","bank official",
            "पुलिस","सरकार","सरकारी अधिकारी","बैंक अधिकारी","अधिकृत नोटिस",
            "पोलीस","सरकार","शासकीय अधिकारी","बँक अधिकारी","अधिकृत नोटीस"
        ],
        points:22,icon:"👮",type:"Authority Impersonation"
    },
    personal:{
        words:[
            "dear customer","account holder","user id","reference number",
            "प्रिय ग्राहक","ग्राहक महोदय","खाता धारक","उपयोगकर्ता आईडी","संदर्भ संख्या",
            "प्रिय ग्राहक","आदरणीय ग्राहक","खातेधारक","युझर आयडी","संदर्भ क्रमांक"
        ],
        points:15,icon:"📝",type:"Impersonal Greeting"
    }
};

// classify a single URL as safe / suspicious
function classifyLink(url){
    let hostname = "";
    try{
        const cleaned = url.replace(/[\[\]\(\)]/g,"");
        const u = new URL(cleaned);
        hostname = u.hostname.toLowerCase();
    }catch(e){
        return {safe:false, reason:"Invalid URL"};
    }

    const trusted = [
        "paypal.com",
        "www.paypal.com"
    ];

    const isTrusted = trusted.some(dom => hostname === dom || hostname.endsWith("."+dom));

    if(isTrusted){
        return {safe:true, reason:"Known PayPal domain"};
    }

    const suspiciousPatterns = [
        "paypal-",
        "paypalsecure",
        "paypal-security",
        "secure-verification",
        "verification",
        "verify",
        "login",
        "update"
    ];

    const isSuspicious =
        hostname.includes("paypal") &&
        !isTrusted &&
        suspiciousPatterns.some(p => hostname.includes(p));

    return {
        safe: !isSuspicious,
        reason: isSuspicious ? "Impersonating PayPal with suspicious hostname" : "Unrecognized domain"
    };
}

function analyze(){
    const text=document.getElementById("message").value.trim();
    if(!text){alert("Please paste a message to analyze.");return;}

    let score=0;
    let detected=[];
    let suspiciousWords=new Set();
    const lower=text.toLowerCase();

    const urlPattern=/https?:\/\/[^\s<>"']{5,}/gi;
    const links=text.match(urlPattern)||[];

    const categoryCounts={urgency:0,fear:0,reward:0,finance:0,authority:0,personal:0};

    Object.entries(patterns).forEach(([key,{words,points,icon,type}])=>{
        words.forEach(word=>{
            if(lower.includes(word)){
                score+=points;
                detected.push({icon,type,word,category:key});
                suspiciousWords.add(word);
                categoryCounts[key]+=points;
            }
        });
    });

    let suspiciousLinkCount = 0;
    const linkDetails = links.map(link=>{
        const cls = classifyLink(link);
        if(!cls.safe){
            suspiciousLinkCount++;
            score += 30;
            detected.push({
                icon:"🔗",
                type:"Suspicious Link",
                word:link,
                category:"links",
                linkSafe:false,
                reason:cls.reason
            });
        }else{
            detected.push({
                icon:"🔗",
                type:"Safe/Trusted Link",
                word:link,
                category:"links",
                linkSafe:true,
                reason:cls.reason
            });
        }
        return {url:link, ...cls};
    });

    if(text.length<100 && score>30) score+=15;

    score=Math.min(score,100);

    const riskData=getRiskLevel(score);
    const highlighted=highlightText(text,Array.from(suspiciousWords));
    const scamType=getScamType(detected);
    const advice=getAdvice(riskData.level);

    renderOutput(
        riskData,
        score,
        detected,
        highlighted,
        links,
        linkDetails,
        scamType,
        advice,
        categoryCounts,
        suspiciousLinkCount
    );
}

function getRiskLevel(score){
    if(score>70) return{level:"HIGH",class:"danger",text:"CRITICAL THREAT"};
    if(score>40) return{level:"MEDIUM",class:"suspicious",text:"SUSPICIOUS"};
    return{level:"LOW",class:"safe",text:"LOW RISK"};
}

function getScamType(detected){
    const types=detected.map(d=>d.type.toLowerCase());
    if(types.some(t=>t.includes("financial")))return"💳 Banking/Payment Scam";
    if(types.some(t=>t.includes("reward")))return"🎁 Lottery/Prize Scam";
    if(types.some(t=>t.includes("fear")))return"🚨 Account Lockout Scam";
    if(types.some(t=>t.includes("urgency")))return"⚡ Time-Sensitive Scam";
    return"📧 Generic Phishing";
}

function getAdvice(level){
    const adv={
        HIGH:"❌ <strong>Do NOT click any links.</strong> Multiple phishing indicators detected. Verify identity only via official website/app, not this message.",
        MEDIUM:"⚠️ <strong>Be very cautious.</strong> Confirm the request via another channel. Check sender address/domain carefully before taking any action.",
        LOW:"✅ <strong>Looks relatively safe,</strong> but stay alert. Avoid sharing sensitive data unless you are 100% sure of the sender."
    };
    return adv[level];
}

function highlightText(text,words){
    let highlighted=text;
    words.forEach(word=>{
        const safeWord = word.replace(/[.*+?^${}()|[\]\\]/g,"\\$&");
        const regex=new RegExp("("+safeWord+")","gi");
        highlighted=highlighted.replace(regex,'<span class="highlight">$1</span>');
    });
    return highlighted;
}

function renderOutput(
    riskData,
    score,
    detected,
    highlighted,
    links,
    linkDetails,
    scamType,
    advice,
    categoryCounts,
    suspiciousLinkCount
){
    const output=document.getElementById("output");
    const riskPercent=Math.round(score);

    const indicators=detected.filter(d=>d.category!=="links").length;
    const uniqueTriggers=new Set(detected.filter(d=>d.category!=="links").map(d=>d.word)).size;
    const linkCount=links.length;

    const maxCat=Math.max(...Object.values(categoryCounts),1);

    output.innerHTML=`
        <div class="summary-row">
            <div class="summary-pill ${riskData.class==='danger'?'danger':riskData.class==='suspicious'?'warn':'safe'}">
                <div><span class="label">Overall Risk</span><br><span class="value">${riskPercent}%</span></div>
            </div>
            <div class="summary-pill warn">
                <div><span class="label">Language Risk</span><br><span class="value">${indicators}</span></div>
            </div>
            <div class="summary-pill ${suspiciousLinkCount>0?'danger':'safe'}">
                <div><span class="label">Suspicious Links</span><br><span class="value">${suspiciousLinkCount}/${linkCount}</span></div>
            </div>
        </div>

        <div class="risk-badge ${riskData.class}">
            <i class="fas ${riskData.level==='HIGH'?'fa-triangle-exclamation':riskData.level==='MEDIUM'?'fa-circle-exclamation':'fa-circle-check'}"></i>
            ${riskData.text}
        </div>

        <div class="top-layout">
            <div class="gauge-wrapper">
                <div class="gauge-label">Risk Gauge</div>
                <div class="gauge">
                    <svg width="150" height="80">
                        <defs>
                            <linearGradient id="gaugeGradient" x1="0%" y1="0%" x2="100%" y2="0%">
                                <stop offset="0%" stop-color="#22c55e"/>
                                <stop offset="50%" stop-color="#facc15"/>
                                <stop offset="100%" stop-color="#ef4444"/>
                            </linearGradient>
                        </defs>
                        <path d="M15 75 A 60 60 0 0 1 135 75" fill="none" stroke="url(#gaugeGradient)" stroke-width="12" stroke-linecap="round"/>
                        <circle cx="75" cy="75" r="4" fill="#e5e7eb"/>
                        <line id="needle" class="gauge-needle" x1="75" y1="75" x2="75" y2="20" stroke="#e5e7eb" stroke-width="3" stroke-linecap="round"/>
                    </svg>
                </div>
                <div class="gauge-value">${riskPercent}%</div>
            </div>

            <div class="top-right">
                <div>
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
                        <span class="gauge-label">Phishing Risk Score</span>
                        <span style="font-size:.9rem;color:#e5e7eb;">${riskPercent}%</span>
                    </div>
                    <div class="risk-meter ${riskData.class}">
                        <div class="risk-fill" style="width:${riskPercent}%"></div>
                    </div>
                </div>

                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-label">Threat Indicators</div>
                        <div class="stat-number">${indicators}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Unique Triggers</div>
                        <div class="stat-number">${uniqueTriggers}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Links</div>
                        <div class="stat-number">${linkCount}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Scam Type</div>
                        <div class="stat-number" style="font-size:1rem;">${scamType}</div>
                    </div>
                </div>
            </div>
        </div>

        <div class="threat-row">
            <div class="threat-timeline">
                <h3>Threat Timeline</h3>
                ${
                    indicators
                    ? detected
                        .filter(d=>d.category!=="links")
                        .slice(0,8)
                        .map(d=>`
                        <div class="threat-item">
                            <div class="threat-icon">${d.icon}</div>
                            <div>
                                <div style="font-weight:600;">${d.type}</div>
                                <div style="font-size:.85rem;color:#9ca3af;">Triggered by: "${d.word}"</div>
                            </div>
                        </div>
                    `).join("")
                    : '<div style="padding:18px;text-align:center;color:#9ca3af;">No obvious phishing language detected ✅</div>'
                }
            </div>

            <div class="chart-card">
                <h3>Category Risk Bars</h3>
                ${
                    ["urgency","fear","reward","finance","authority","personal"].map(key=>{
                        const perc=Math.round((categoryCounts[key]/maxCat)*100)||0;
                        const label=key.charAt(0).toUpperCase()+key.slice(1);
                        return `
                        <div class="bar-row">
                            <div class="bar-label">${label}</div>
                            <div class="bar-track">
                                <div class="bar-fill bar-${key}" style="width:${perc}%;"></div>
                            </div>
                            <div style="font-size:.75rem;color:#9ca3af;width:30px;text-align:right;">${perc}%</div>
                        </div>`;
                    }).join("")
                }
            </div>
        </div>

        <div>
            <h3 style="font-size:.95rem;text-transform:uppercase;letter-spacing:.16em;color:#9ca3af;margin-top:20px;">Original Message (Highlighted)</h3>
            <div class="highlight-section"><pre>${highlighted}</pre></div>
        </div>

        ${links.length>0?`
        <div class="links-list">
            <h3 style="font-size:.9rem;text-transform:uppercase;letter-spacing:.16em;color:#9ca3af;margin-bottom:6px;">Detected Links (${links.length})</h3>
            ${linkDetails.map(ld=>{
                const display = ld.url.replace(/https?:\/\//,"");
                const encoded = ld.url.replace(/'/g,"&#39;");
                const badge = ld.safe ? "SAFE" : "SUSPICIOUS";
                const badgeColor = ld.safe ? "#22c55e" : "#ef4444";
                return `
                <div class="link-item"
                     onclick="navigator.clipboard.writeText('${encoded}'); this.textContent='Copied!'; setTimeout(()=>this.textContent='${display}  [${badge}]',1400);"
                     style="border-left:4px solid ${badgeColor};">
                    ${ld.url}  [${badge}] - ${ld.reason}
                </div>`;
            }).join("")}
        </div>`:""}

        <div class="advice ${riskData.class==='danger'?'danger-advice':''}">
            <h3><i class="fas fa-lightbulb"></i> Security Advice</h3>
            <p style="margin-top:6px;font-size:.95rem;">${advice}</p>
        </div>

        <div class="footer-actions">
            <button class="btn btn-secondary" onclick="downloadReport()" style="padding-inline:30px;">
                <i class="fas fa-download"></i> Download Report
            </button>
        </div>
    `;

    output.style.display="block";
    output.scrollIntoView({behavior:"smooth"});

    const needle=document.getElementById("needle");
    const angle=(riskPercent/100)*180-90;
    needle.style.transform=`rotate(${angle}deg)`;
}

function downloadReport(){
    const output=document.getElementById("output");
    if(output.style.display==="none"||!output.innerText.trim()){
        alert("Run an analysis before downloading the report.");
        return;
    }
    const text=document.getElementById("message").value;
    const riskLine=output.querySelector(".summary-pill .value").textContent.trim();
    const threatText=output.querySelector(".risk-badge").textContent.trim();
    const advice=output.querySelector(".advice").innerText.trim();

    const report=`PhishGuard Pro - Analysis Report
==================================================

Overall Risk Score : ${riskLine}
Threat Level       : ${threatText}
Generated At       : ${new Date().toLocaleString()}

Original Message
----------------
${text}

Security Advice
---------------
${advice}

(Generated by PhishGuard Pro - HTML/JS phishing detector)
`;

    const blob=new Blob([report],{type:"text/plain;charset=utf-8"});
    const link=document.createElement("a");
    link.href=URL.createObjectURL(blob);
    link.download=`phishguard-report-${Date.now()}.txt`;
    link.click();
}

function clearAll(){
    document.getElementById("message").value="";
    document.getElementById("output").style.display="none";
    document.getElementById("output").innerHTML="";
    document.getElementById("message").focus();
}

function loadDemo(){
    document.getElementById("message").value=`Hello Customer,

We noticed a recent login to your account from a new device.
For your security, please review the activity and confirm that it was you.
You can check your account activity here:
https://www.paypal.com/activity
For security guidelines, please visit our help center:
https://www.paypal.com/security
⚠ If you do not recognize this activity, verify your account immediately using the secure link below to prevent suspension:
http://paypal-secure-verification-alert.com/login

Thank you,
PayPal Security Team`;
    document.getElementById("message").focus();
    setTimeout(analyze,400);
}

window.addEventListener("load",()=>{
    setTimeout(()=>{
        if(!document.getElementById("message").value.trim()){
            loadDemo();
        }
    },800);
});
